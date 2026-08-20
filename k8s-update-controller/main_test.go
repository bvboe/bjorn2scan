package main

import (
	"os"
	"path/filepath"
	"testing"

	"helm.sh/helm/v4/pkg/kube"
)

// TestPinHelmFieldManager guards against a silent regression that broke every
// Helm upgrade across the fleet.
//
// Helm v4 defaults to server-side apply, which enforces managedFields ownership.
// When kube.ManagedFieldsManager is empty, Helm falls back to
// filepath.Base(os.Args[0]) — so this binary would apply as
// "k8s-update-controller" and conflict with the "helm"-owned labels that the CLI
// put on every chart resource. Nothing in the build or the type system catches
// that; the first symptom is upgrades failing in production.
func TestPinHelmFieldManager(t *testing.T) {
	original := kube.ManagedFieldsManager
	t.Cleanup(func() { kube.ManagedFieldsManager = original })

	kube.ManagedFieldsManager = ""
	pinHelmFieldManager()

	if kube.ManagedFieldsManager != "helm" {
		t.Errorf("kube.ManagedFieldsManager = %q, want \"helm\" — the controller must apply "+
			"under the same identity as the Helm CLI or server-side apply will reject every upgrade",
			kube.ManagedFieldsManager)
	}

	// The fallback Helm would otherwise use. Asserting they differ is what makes
	// this test meaningful: if the binary were somehow named "helm", the bug could
	// hide and the pin would look unnecessary.
	fallback := filepath.Base(os.Args[0])
	if fallback == "helm" {
		t.Skipf("test binary is named %q, so the fallback coincides with the pinned value", fallback)
	}
	if kube.ManagedFieldsManager == fallback {
		t.Errorf("pinned manager %q equals the os.Args[0] fallback; the pin is not doing anything",
			kube.ManagedFieldsManager)
	}
}
