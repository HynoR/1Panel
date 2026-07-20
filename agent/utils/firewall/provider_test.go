package firewall

import (
	"strings"
	"testing"
)

func TestLaneOfName(t *testing.T) {
	if LaneOfName("iptables") != LaneSelfManagedLegacyV1 {
		t.Fatal("iptables must be legacy-v1")
	}
	if LaneOfName("ufw") != LaneExternalNative {
		t.Fatal("ufw must be external")
	}
	if LaneOfName("firewalld") != LaneExternalNative {
		t.Fatal("firewalld must be external")
	}
}

func TestResolveProviderFromPresence(t *testing.T) {
	tests := []struct {
		name      string
		firewalld bool
		ufw       bool
		iptables  bool
		wantName  string
		wantLane  Lane
		wantErr   string
	}{
		{
			name:      "firewalld preferred",
			firewalld: true,
			wantName:  "firewalld",
			wantLane:  LaneExternalNative,
		},
		{
			name:     "ufw external",
			ufw:      true,
			wantName: "ufw",
			wantLane: LaneExternalNative,
		},
		{
			name:     "iptables legacy",
			iptables: true,
			wantName: "iptables",
			wantLane: LaneSelfManagedLegacyV1,
		},
		{
			name:      "conflict",
			firewalld: true,
			ufw:       true,
			wantErr:   "both firewalld and ufw",
		},
		{
			name:    "none",
			wantErr: "No system firewall service detected",
		},
		{
			name:      "firewalld wins over iptables",
			firewalld: true,
			iptables:  true,
			wantName:  "firewalld",
			wantLane:  LaneExternalNative,
		},
		{
			name:     "ufw wins over iptables",
			ufw:      true,
			iptables: true,
			wantName: "ufw",
			wantLane: LaneExternalNative,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveProviderFromPresence(tt.firewalld, tt.ufw, tt.iptables)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tt.wantName || got.Lane != tt.wantLane {
				t.Fatalf("got %+v want name=%s lane=%s", got, tt.wantName, tt.wantLane)
			}
			if tt.wantLane == LaneExternalNative && !got.IsExternal() {
				t.Fatal("expected IsExternal")
			}
			if tt.wantLane == LaneSelfManagedLegacyV1 && !got.IsLegacyV1() {
				t.Fatal("expected IsLegacyV1")
			}
		})
	}
}
