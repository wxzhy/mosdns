package coremain

import "testing"

func TestInstanceProbeManagerOwnership(t *testing.T) {
	m := NewTestMosdnsWithPlugins(nil)
	if m.ProbeManager() != m.ProbeManager() {
		t.Fatal("selectors do not share a manager")
	}
	m.CloseWithErr(nil)
	if err := m.GetSafeClose().WaitClosed(); err != nil {
		t.Fatal(err)
	}
	// Getter remains safe after shutdown, including first access after shutdown.
	m2 := NewTestMosdnsWithPlugins(nil)
	m2.CloseWithErr(nil)
	_ = m2.ProbeManager()
}
