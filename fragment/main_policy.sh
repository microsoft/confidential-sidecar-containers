#!/usr/bin/env bash

cat > aci_import_rules.json <<'EOF'
{
    "fragments": [
        {
            "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
            "includes": [
                "containers",
                "fragments"
            ],
            "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
            "minimum_svn": "4"
        }
    ]
}
EOF

cat <<'EOF'
package policy

import future.keywords.every
import future.keywords.in

api_version := "0.11.0"
framework_version := "0.5.0"

EOF

echo -n 'fragments := '
cat *_import_rules.json | jq -sr '[.[].fragments[]]'

cat <<'EOF'

allow_properties_access := true
allow_dump_stacks := true
allow_runtime_logging := true
allow_environment_variable_dropping := true
allow_unencrypted_scratch := false
allow_capability_dropping := true

mount_device := data.framework.mount_device
unmount_device := data.framework.unmount_device
mount_overlay := data.framework.mount_overlay
unmount_overlay := data.framework.unmount_overlay
create_container := data.framework.create_container
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
get_properties := data.framework.get_properties
dump_stacks := data.framework.dump_stacks
runtime_logging := data.framework.runtime_logging
load_fragment := data.framework.load_fragment
scratch_mount := data.framework.scratch_mount
scratch_unmount := data.framework.scratch_unmount

reason := {"errors": data.framework.errors}

EOF
