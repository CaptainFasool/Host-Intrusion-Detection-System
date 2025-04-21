#!/bin/bash

FILES=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/group")

if [[ ! -s digests.sha256 ]]; then
	touch digests.sha256
	for file in "${FILES[@]}"; do
        if ! grep -q "$file" digests.sha256; then
                sudo sha256sum "$file" >> digests.sha256
        fi
	done
	echo "File hashes saved."
fi

if ! sudo sha256sum --check digests.sha256 &> /dev/null; then # Hash check will return true if no mismatches; false if there are mismatches
	echo "$(date): Violation of integrity from file hash mismatch: $(sudo sha256sum --check digests.sha256 | grep FAILED)" | tee -a alerts.log
fi
