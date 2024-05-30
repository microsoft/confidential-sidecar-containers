package policy

import future.keywords.every
import future.keywords.in

api_version := "0.10.0"
framework_version := "0.2.3"

fragments := [
  {
    "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
    "minimum_svn": "1"
  }
]

containers := [{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["python3","primary.py"],"env_rules":[{"pattern":"PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"LANG=C.UTF-8","required":false,"strategy":"string"},{"pattern":"GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305","required":false,"strategy":"string"},{"pattern":"PYTHON_VERSION=3.12.3","required":false,"strategy":"string"},{"pattern":"PYTHON_PIP_VERSION=24.0","required":false,"strategy":"string"},{"pattern":"PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py","required":false,"strategy":"string"},{"pattern":"PYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"}],"exec_processes":[],"id":"confidentialsidecars.azurecr.io/attestation/primary:dom","layers":["8e978a1d2dbb44e1ff09eb8edc611f716bb4307c9c1b7583302d94d34daa007f","1fe6d4527bbaefd3f85b423530ec202b737a70cfae5ecd2280b944b53375979f","df13c8a3bf4ab0cdfc66fa3539ea890a7395ffff908cbb2fa1f52b7765d58399","38b7ef46db0f0423b0ac4177431b4a13c79836526f9a1076f44fc75a679c189b","9b66ec4d8dc6841b1679eb2881dbc145d6fd7edb28b35cddfae55e2b3bf61a1b","d3bce44351aa0ee9d9d593be3e2469fe935b86411f82dcf0f0c55dffa8a022f1","5bbe3299f3725b77e2982cc6098de2c823ec3b5874d8ae2b8e91755997f92069","6f0f555d7f32e2606bbb386f2bf1e5680ff9bfb302d6833d09fda80c3840ea55","c64ef35897dcaeb613ac951d151cb714f75d0da92218c1dd7ddfecbfcaadda72","8fbe9bd0b31ffe694f1df80c3ea10560ce8196e46e2ae7033be2c62fb91b0d56","a21aad6c64adc4a71a62c326ae4bcaee649b6b801978df256aa7ae758be120e8","b338bfc2912c413e2e5e0b95d833f5080ab05c02495e732a230c0252b76169f7","4be1855db35c90b2bb79747efb3bc475108990b1745a828bf5a83ce7b53207c3"],"mounts":[{"destination":"/mnt/uds","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/emptydir/.+","type":"bind"},{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"attestation-primary","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/usr/src/app"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["app","-socket-address","/mnt/uds/sock"],"env_rules":[{"pattern":"AZURE_ATTESTATION_ENDPOINT=caciexamples.eus.attest.azure.net","required":false,"strategy":"string"},{"pattern":"PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"GOLANG_VERSION=1.22.1","required":false,"strategy":"string"},{"pattern":"GOPATH=/go","required":false,"strategy":"string"},{"pattern":"GOEXPERIMENT=systemcrypto,allowcryptofallback","required":false,"strategy":"string"},{"pattern":"GOOS=linux","required":false,"strategy":"string"},{"pattern":"CGO_ENABLED=0","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"}],"exec_processes":[],"id":"confidentialsidecars.azurecr.io/attestation/sidecar:dom","layers":["5204e5476abb6a0214447dac2907f818c4cf0ffb2350bd53afa9d31eb7c3f0ea","fef2a5f60cb73f637443d529c99bdca4075528e185ec294155aff1744cbac538","59cea8f0d212d571239b24d20f510c74186468f6d63d4b370e70017a48acdc30","36c8e67f92cdb9d3c262a4103d73b366393c1fd22704b2da4904a0c68dc287c9","2ef6b94236f185cc9e0b296707755a699d59c2dd8eaad946a85db7072321922f","8b4842f06982817534a75bcf71865213b09dfa8313229c384e5201dadbd75e25","df4e87462f192f54d4b001fea2aaf385118a570b86a27583a66436b7bc78ae70","6becfae733078a901cd8872e50c6eb69d838701920150372796474d2f8803c00","c10d6a5548770291472a289f490dccee57d29b72d5954c063ad2e5a53c56a304"],"mounts":[{"destination":"/mnt/uds","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/emptydir/.+","type":"bind"},{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"attestation-sidecar","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/usr/src/app"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"inheritable":[],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"command":["/pause"],"env_rules":[{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":true,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"}],"exec_processes":[],"layers":["16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"],"mounts":[],"no_new_privileges":false,"seccomp_profile_sha256":"","signals":[],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"}]

allow_properties_access := true
allow_dump_stacks := false
allow_runtime_logging := false
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


