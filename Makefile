# ============================================================================
#  PHP2Shell Lab — atajos make (TODO delega en p2s.sh, el script único)
#  Si prefieres make, usa estos; la lógica vive 100% en ./p2s.sh
# ============================================================================
CMD ?= id

.PHONY: help up down status logs clean test test-vuln test-patched iocs \
        info check rce rce-canonical demo vendor

help:            ; @./p2s.sh help
up:              ; @./p2s.sh up
down:            ; @./p2s.sh down
stop:            ; @./p2s.sh down
status:          ; @./p2s.sh status
logs:            ; @./p2s.sh logs
clean:           ; @./p2s.sh clean
test:            ; @./p2s.sh test all
test-vuln:       ; @./p2s.sh test vuln
test-patched:    ; @./p2s.sh test patched
iocs:            ; @./p2s.sh iocs
info:            ; @./p2s.sh info
check:           ; @./p2s.sh check
rce:             ; @./p2s.sh rce "$(CMD)"
rce-canonical:   ; @./p2s.sh rce-canonical
demo:            ; @./p2s.sh demo
vendor:          ; @./p2s.sh vendor
