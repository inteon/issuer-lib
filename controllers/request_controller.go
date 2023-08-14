/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
)

// RequestController reconciles a Request object
type RequestController struct {
	IssuerTypes        []v1alpha1.Issuer
	ClusterIssuerTypes []v1alpha1.Issuer

	FieldOwner       string
	MaxRetryDuration time.Duration
	EventSource      kubeutil.EventSource

	// Client is a controller-runtime client used to get and set K8S API resources
	client.Client
	// Sign connects to a CA and returns a signed certificate for the supplied Request.
	signer.Sign
	// IgnoreRequest is an optional function that can prevent the Request
	// and Kubernetes CSR controllers from reconciling a Request resource.
	signer.IgnoreRequest

	// EventRecorder is used for creating Kubernetes events on resources.
	EventRecorder record.EventRecorder

	// Clock is used to mock condition transition times in tests.
	Clock clock.PassiveClock

	PostSetupWithManager func(context.Context, schema.GroupVersionKind, ctrl.Manager, controller.Controller) error

	allIssuerTypes []IssuerType

	initialised                bool
	requestType                client.Object
	requestPredicate           predicate.Predicate
	matchIssuerType            MatchIssuerType
	requestObjectHelperCreator RequestObjectHelperCreator
}

type MatchIssuerType func(client.Object) (v1alpha1.Issuer, client.ObjectKey, error)
type RequestObjectHelperCreator func(client.Object) RequestObjectHelper

type IssuerType struct {
	Type         v1alpha1.Issuer
	IsNamespaced bool
}

func (r *RequestController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithName("Reconcile")

	logger.V(2).Info("Starting reconcile loop", "name", req.Name, "namespace", req.Namespace)

	statusPatch, returnedError := r.reconcileStatusPatch(logger, ctx, req)

	if statusPatch == nil {
		logger.V(2).Info("Got empty StatusPatch result", "error", returnedError)
		return ctrl.Result{}, returnedError
	}

	logger.V(2).Info("Got StatusPatch result", "error", returnedError)

	obj, patch, err := statusPatch.Patch()
	if err != nil {
		return ctrl.Result{}, utilerrors.NewAggregate([]error{err, returnedError}) // requeue with backoff
	}

	if err := r.Client.Status().Patch(ctx, obj, patch, &client.SubResourcePatchOptions{
		PatchOptions: client.PatchOptions{
			FieldManager: r.FieldOwner,
			Force:        ptr.To(true),
		},
	}); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, utilerrors.NewAggregate([]error{err, returnedError}) // requeue with backoff
		}

		logger.V(1).Info("Request not found. Ignoring.")
		return ctrl.Result{}, nil // done
	}

	return ctrl.Result{}, returnedError
}

func (r *RequestController) reconcileStatusPatch(
	logger logr.Logger,
	ctx context.Context,
	req ctrl.Request,
) (_ RequestPatch, returnedError error) {
	requestObject := r.requestType.DeepCopyObject().(client.Object)

	if err := r.Client.Get(ctx, req.NamespacedName, requestObject); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Request not found. Ignoring.")
		return nil, nil // done
	} else if err != nil {
		return nil, fmt.Errorf("unexpected get error: %v", err) // requeue with backoff
	}

	// Select first matching issuer type and construct an issuerObject and issuerName
	issuerObject, issuerName, err := r.matchIssuerType(requestObject)
	// Ignore Request if issuerRef doesn't match one of our issuer Types
	if err != nil {
		logger.V(1).Info("Request has a foreign issuer. Ignoring.", "error", err)
		return nil, nil // done
	}
	issuerGvk := issuerObject.GetObjectKind().GroupVersionKind()

	// Create a helper for the requestObject
	requestObjectHelper := r.requestObjectHelperCreator(requestObject)

	// Ignore Request if it has not yet been assigned an approval
	// status condition by an approval controller.
	if !requestObjectHelper.IsApproved() && !requestObjectHelper.IsDenied() {
		logger.V(1).Info("Request has not been approved or denied. Ignoring.")
		return nil, nil // done
	}

	// Ignore Request if it is already Ready
	if requestObjectHelper.IsReady() {
		logger.V(1).Info("Request is Ready. Ignoring.")
		return nil, nil // done
	}

	// Ignore Request if it is already Failed
	if requestObjectHelper.IsFailed() {
		logger.V(1).Info("Request is Failed. Ignoring.")
		return nil, nil // done
	}

	// Ignore Request if it is already Denied
	if requestObjectHelper.IsDenied() {
		logger.V(1).Info("Request is Denied. Ignoring.")
		return nil, nil // done
	}

	if r.IgnoreRequest != nil {
		ignore, err := r.IgnoreRequest(
			ctx,
			requestObjectHelper.RequestObject(),
			issuerGvk,
			issuerName,
		)
		if err != nil {
			logger.V(1).Error(err, "Unexpected error while checking if Request should be ignored")
			return nil, fmt.Errorf("failed to check if Request should be ignored: %v", err) // requeue with backoff
		}

		if ignore {
			logger.V(1).Info("Ignoring Request")
			return nil, nil // done
		}
	}

	// We now have a Request that belongs to us so we are responsible
	// for updating its Status.
	statusPatch := requestObjectHelper.NewPatch(
		r.Clock,
		r.FieldOwner,
		r.EventRecorder,
	)

	// Add a Ready condition if one does not already exist. Set initial Status
	// to Unknown.
	if statusPatch.SetInitializing() {
		logger.V(1).Info("Initialised Ready condition")

		// To continue reconciling this Request, we must re-run the reconcile loop
		// after adding the Unknown Ready condition. This update will trigger a
		// new reconcile loop, so we don't need to requeue here.
		return statusPatch, nil // apply patch, done
	}

	if err := r.Client.Get(ctx, issuerName, issuerObject); err != nil && apierrors.IsNotFound(err) {
		logger.V(1).Info("Issuer not found. Waiting for it to be created")
		statusPatch.SetWaitingForIssuerExist(err)

		return statusPatch, nil // apply patch, done
	} else if err != nil {
		logger.V(1).Error(err, "Unexpected error while getting Issuer")
		statusPatch.SetUnexpectedError(err)

		return nil, fmt.Errorf("unexpected get error: %v", err) // requeue with backoff
	}

	readyCondition := conditions.GetIssuerStatusCondition(
		issuerObject.GetStatus().Conditions,
		cmapi.IssuerConditionReady,
	)
	if readyCondition == nil {
		logger.V(1).Info("Issuer is not Ready yet (no ready condition). Waiting for it to become ready.")
		statusPatch.SetWaitingForIssuerReadyNoCondition()

		return statusPatch, nil // apply patch, done
	}
	if readyCondition.ObservedGeneration < issuerObject.GetGeneration() {
		logger.V(1).Info("Issuer is not Ready yet (ready condition out-of-date). Waiting for it to become ready.", "issuer ready condition", readyCondition)
		statusPatch.SetWaitingForIssuerReadyOutdated()

		return statusPatch, nil // apply patch, done
	}
	if readyCondition.Status != cmmeta.ConditionTrue {
		logger.V(1).Info("Issuer is not Ready yet (status == false). Waiting for it to become ready.", "issuer ready condition", readyCondition)
		statusPatch.SetWaitingForIssuerReadyNotReady(readyCondition)

		return statusPatch, nil // apply patch, done
	}

	signedCertificate, err := r.Sign(log.IntoContext(ctx, logger), requestObjectHelper.RequestObject(), issuerObject)
	if err == nil {
		logger.V(1).Info("Successfully finished the reconciliation.")
		statusPatch.SetIssued(signedCertificate)

		return statusPatch, nil // apply patch, done
	}

	// An error in the issuer part of the operator should trigger a reconcile
	// of the issuer's state.
	if issuerError := new(signer.IssuerError); errors.As(err, issuerError) {
		if reportError := r.EventSource.ReportError(
			issuerGvk, client.ObjectKeyFromObject(issuerObject),
			issuerError.Err,
		); reportError != nil {
			err = utilerrors.NewAggregate([]error{err, reportError})
		}

		logger.V(1).Info("Issuer is not Ready yet (ready condition out-of-date). Waiting for it to become ready.", "issuer-error", issuerError)
		statusPatch.SetWaitingForIssuerReadyOutdated()

		return statusPatch, nil // apply patch, done
	}

	didCustomConditionTransition := false
	if targetCustom := new(signer.SetRequestConditionError); errors.As(err, targetCustom) {
		logger.V(1).Info("Set RequestCondition error. Setting condition.", "error", err)
		didCustomConditionTransition = statusPatch.SetCustomCondition(targetCustom.ConditionType, targetCustom.ConditionStatus, targetCustom.ConditionReason, targetCustom.Error())
	}

	// Check if we have still time to requeue & retry
	isPendingError := errors.As(err, &signer.PendingError{})
	isPermanentError := errors.As(err, &signer.PermanentError{})
	pastMaxRetryDuration := r.Clock.Now().After(requestObject.GetCreationTimestamp().Add(r.MaxRetryDuration))
	if !isPendingError && (isPermanentError || pastMaxRetryDuration) {
		// fail permanently
		logger.V(1).Error(err, "Permanent Request error. Marking as failed.")
		statusPatch.SetPermanentError(err)

		return statusPatch, reconcile.TerminalError(err) // apply patch, done
	} else {
		// retry
		logger.V(1).Error(err, "Retryable Request error.")
		statusPatch.SetRetryableError(err)

		if didCustomConditionTransition {
			// the reconciliation loop will be retriggered because of the added/ changed custom condition
			return statusPatch, reconcile.TerminalError(err) // apply patch, done
		} else {
			return statusPatch, err // apply patch, requeue with backoff
		}
	}
}

func (r *RequestController) setAllIssuerTypesWithGroupVersionKind(scheme *runtime.Scheme) error {
	issuers := make([]IssuerType, 0, len(r.IssuerTypes)+len(r.ClusterIssuerTypes))
	for _, issuer := range r.IssuerTypes {
		issuers = append(issuers, IssuerType{
			Type:         issuer,
			IsNamespaced: true,
		})

	}
	for _, issuer := range r.ClusterIssuerTypes {
		issuers = append(issuers, IssuerType{
			Type:         issuer,
			IsNamespaced: false,
		})
	}

	for _, issuer := range issuers {
		if err := kubeutil.SetGroupVersionKind(scheme, issuer.Type); err != nil {
			return err
		}
	}

	r.allIssuerTypes = issuers

	return nil
}

func (r *RequestController) AllIssuerTypes() []IssuerType {
	return r.allIssuerTypes
}

func (r *RequestController) Init(
	requestType client.Object,
	requestPredicate predicate.Predicate,
	matchIssuerType MatchIssuerType,
	requestObjectHelperCreator RequestObjectHelperCreator,
) *RequestController {
	r.requestType = requestType
	r.requestPredicate = requestPredicate
	r.matchIssuerType = matchIssuerType
	r.requestObjectHelperCreator = requestObjectHelperCreator

	r.initialised = true

	return r
}

// SetupWithManager sets up the controller with the Manager.
func (r *RequestController) SetupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
) error {
	if !r.initialised {
		return fmt.Errorf("must call Init(...) before calling SetupWithManager(...)")
	}

	if err := kubeutil.SetGroupVersionKind(mgr.GetScheme(), r.requestType); err != nil {
		return err
	}

	if err := r.setAllIssuerTypesWithGroupVersionKind(mgr.GetScheme()); err != nil {
		return err
	}

	build := ctrl.
		NewControllerManagedBy(mgr).
		For(
			r.requestType,
			// We are only interested in changes to the non-ready conditions of the
			// certificaterequest, this also prevents us to get in fast reconcile loop
			// when setting the status to Pending causing the resource to update, while
			// we only want to re-reconcile with backoff/ when a resource becomes available.
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				r.requestPredicate,
			),
		)

	// We watch all the issuer types. When an issuer receives a watch event, we
	// reconcile all the certificate requests that reference that issuer. This
	// is useful when the certificate request undergoes long backoff retry
	// periods and wouldn't react quickly to a fix in the issuer configuration.
	for _, issuerType := range r.AllIssuerTypes() {
		issuerType := issuerType
		gvk := issuerType.Type.GetObjectKind().GroupVersionKind()

		// This context is passed through to the client-go informer factory and the
		// timeout dictates how long to wait for the informer to sync with the K8S
		// API server. See:
		// * https://github.com/kubernetes-sigs/controller-runtime/issues/562
		// * https://github.com/kubernetes-sigs/controller-runtime/issues/1219
		//
		// The defaulting logic is based on:
		// https://github.com/kubernetes-sigs/controller-runtime/blob/30eae58f1b984c1b8139dd9b9f68dd2d530ed429/pkg/controller/controller.go#L138-L144
		timeout := mgr.GetControllerOptions().CacheSyncTimeout
		if timeout == 0 {
			timeout = 2 * time.Minute
		}
		cacheSyncCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resourceHandler, err := kubeutil.NewLinkedResourceHandler(
			cacheSyncCtx,
			mgr.GetLogger(),
			mgr.GetScheme(),
			mgr.GetCache(),
			r.requestType,
			func(rawObj client.Object) []string {
				issuerObject, issuerName, err := r.matchIssuerType(rawObj)
				if err != nil || issuerObject.GetObjectKind().GroupVersionKind() != gvk {
					return nil
				}

				return []string{fmt.Sprintf("%s/%s", issuerName.Namespace, issuerName.Name)}
			},
			nil,
		)
		if err != nil {
			return err
		}

		build = build.Watches(
			issuerType.Type,
			resourceHandler,
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
				LinkedIssuerPredicate{},
			),
		)
	}

	if controller, err := build.Build(r); err != nil {
		return err
	} else if r.PostSetupWithManager != nil {
		err := r.PostSetupWithManager(ctx, r.requestType.GetObjectKind().GroupVersionKind(), mgr, controller)
		r.PostSetupWithManager = nil // free setup function
		return err
	}
	return nil
}
