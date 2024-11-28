package controllers

import (
	"github.com/cert-manager/issuer-lib/internal/kubeutil"
)

func NewEventStore() kubeutil.EventSource {
	return kubeutil.NewEventStore()
}
