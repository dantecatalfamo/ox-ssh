;;; ox-ssh --- SSH Config Backend for Org Export Engine -*- lexical-binding: t; -*-

;; Copyright (C) 2020 Dante Catalfamo

;;; Commentary:

;; TODO

;;; Code:

(require 'ox)

(defgroup org-export-ssh nil
  "Options for exporting Org mode files to SSH config."
  :group 'org-export)

(defcustom org-ssh-header ""
  "Optional text to be inserted at the top of SSH config."
  :type 'text
  :group 'org-export-ssh)

(org-export-define-backend 'ssh
  '((headline . org-ssh-headline)
    (template . org-ssh-template))
  :menu-entry
  '(?s "Export to SSH config"
       ((?s "As Conf buffer" org-ssh-export-as-config))))

(defun org-ssh-headline (headline contents _info)
  "Transform HEADLINE and CONTENTS into SSH config host."
  (let* ((url (org-element-property :URL headline))
         (ip (org-element-property :IP headline))
         (host (org-element-property :raw-value headline))
         (addr (or ip url))
         (ssh-user (org-element-property :SSH_USER headline))
         (ssh-port (org-element-property :SSH_PORT headline))
         (ssh-add-keys-to-agent (org-element-property :SSH_ADD_KEYS_TO_AGENT headline))
         (ssh-address-family (org-element-property :SSH_ADDRESS_FAMILY headline))
         (ssh-batch-mode (org-element-property :SSH_BATCH_MODE headline))
         (ssh-bind-interface (org-element-property :SSH_BIND_INTERFACE headline))
         (ssh-canonical-domains (org-element-property :SSH_CANONICAL_DOMAINS headline))
         (ssh-canonicalize-fallback-local (org-element-property :SSH_CANONICALIZE_FALLBACK_LOCAL headline))
         (ssh-canonicalize-hostname (org-element-property :SSH_CANONICALIZE_HOSTNAME headline))
         (ssh-canonicalize-max-dots (org-element-property :SSH_CANONICALIZE_MAX_DOTS headline))
         (ssh-canonicalize-permitted-cnames (org-element-property :SSH_CANONICALIZE_PERMITTED_CNAMES headline))
         (ssh-ca-signature-algorithms (org-element-property :SSH_CA_SIGNATURE_ALGORITHMS headline))
         (ssh-certificate-file (org-element-property :SSH_CERTIFICATE_FILE headline))
         (ssh-challenge-response-auth (org-element-property :SSH_CHALLENGE_RESPONSE_AUTHENTICATION headline))
         (ssh-check-host-ip (org-element-property :SSH_CHECK_HOST_IP headline))
         (ssh-ciphers (org-element-property :SSH_CIPHERS headline))
         (ssh-clear-all-forwardings (org-element-property :SSH_CLEAR_ALL_FORWARDINGS headline))
         (ssh-compression (org-element-property :SSH_COMPRESSION headline))
         (ssh-connection-attempts (org-element-property :SSH_CONNECTION_ATTEMPTS headline))
         (ssh-connect-timeout (org-element-property :SSH_CONNECT_TIMEOUT headline))
         (ssh-control-master (org-element-property :SSH_CONTROL_MASTER headline))
         (ssh-control-path (org-element-property :SSH_CONTROL_PATH headline))
         (ssh-control-persist (org-element-property :SSH_CONTROL_PERSIST headline))
         (ssh-dynamic-forward (org-element-property :SSH_DYNAMIC_FORWARD headline))
         (ssh-enable-ssh-keysign (org-element-property :SSH_ENABLE_KEYSIGN headline))
         (ssh-escape-char (org-element-property :SSH_ESCAPE_CHAR headline))
         (ssh-exit-on-forward-failure (org-element-property :SSH_EXIT_ON_FORWARD_FAILURE headline))
         (ssh-fingerprint-hash (org-element-property :SSH_FINGERPRINT_HASH headline))
         (ssh-forward-agent (org-element-property :SSH_FORWARD_AGENT headline))
         (ssh-forward-x11 (org-element-property :SSH_FORWARD_X11 headline))
         (ssh-forward-x11-timeout (org-element-property :SSH_FORWARD_X11_TIMEOUT headline))
         (ssh-forward-x11-trusted (org-element-property :SSH_FORWARD_X11_TRUSTED headline))
         (ssh-gateway-ports (org-element-property :SSH_GATEWAY_PORTS headline))
         (ssh-global-known-hosts-file (org-element-property :SSH_GLOBAL_KNOWN_HOSTS_FILE headline))
         (ssh-gssapi-auth (org-element-property :SSH_GSSAPI_AUTHENTICATION headline))
         (ssh-gssapi-delegate-credentials (org-element-property :SSH_GSSAPI_DELEGATE_CREDENTIALS headline))
         (ssh-hash-known-hosts (org-element-property :SSH_HASH_KNOWN_HOSTS headline))
         (ssh-host-based-auth (org-element-property :SSH_HOST_BASED_AUTHENTICATION headline))
         (ssh-host-based-key-types (org-element-property :SSH_HOST_BASED_KEY_TYPES headline))
         (ssh-host-key-algos (org-element-property :SSH_HOST_KEY_ALGORITHMS headline))
         (ssh-host-key-alias (org-element-property :SSH_HOST_KEY_ALIAS headline))
         (ssh-hostname (org-element-property :SSH_HOSTNAME headline))
         (ssh-identities-only (org-element-property :SSH_IDENTITIES_ONLY headline))
         (ssh-identity-agent (org-element-property :SSH_IDENTITY_AGENT headline))
         (ssh-identity-file (org-element-property :SSH_IDENTITY_FILE headline))
         )
    (if addr
        (concat "\nHost " host "\n"
                "  HostName " addr "\n"
                (when ssh-user
                  (concat "  User " ssh-user "\n"))
                (when ssh-port
                  (concat "  Port " ssh-port "\n"))
                (when ssh-add-keys-to-agent
                  (concat "  AddKeysToAgent " ssh-add-keys-to-agent "\n"))
                (when ssh-address-family
                  (concat "  AddressFamily " ssh-address-family "\n"))
                (when ssh-batch-mode
                  (concat "  BatchMode " ssh-batch-mode "\n"))
                (when ssh-bind-interface
                  (concat "  BindInterface " ssh-bind-interface "\n"))
                (when ssh-canonical-domains
                  (concat "  CanonicalDomains " ssh-canonical-domains "\n"))
                (when ssh-canonicalize-fallback-local
                  (concat "  CanonicalizeFallbackLocal" ssh-canonicalize-fallback-local "\n"))
                (when ssh-canonicalize-hostname
                  (concat "  CanonicalizeHostname " ssh-canonicalize-hostname "\n"))
                (when ssh-canonicalize-max-dots
                  (concat "  CanonicalizeMaxDots " ssh-canonicalize-max-dots "\n"))
                (when ssh-canonicalize-permitted-cnames
                  (concat "  CanonicalizePermittedCNAMEs " ssh-canonicalize-permitted-cnames "\n"))
                (when ssh-ca-signature-algorithms
                  (concat "  CASignatureAlgorithms " ssh-ca-signature-algorithms "\n"))
                (when ssh-certificate-file
                  (concat "  CertificateFile " ssh-certificate-file "\n"))
                (when ssh-challenge-response-auth
                  (concat "  ChallengeResponseAuthentication " ssh-challenge-response-auth "\n"))
                (when ssh-check-host-ip
                  (concat "  CheckHostIP " ssh-check-host-ip "\n"))
                (when ssh-ciphers
                  (concat "  Ciphers " ssh-ciphers "\n"))
                (when ssh-clear-all-forwardings
                  (concat "  ClearAllForwardings " ssh-clear-all-forwardings "\n"))
                (when ssh-compression
                  (concat "  Compression " ssh-compression "\n"))
                (when ssh-connection-attempts
                  (concat "  ConnectionAttempts " ssh-connection-attempts "\n"))
                (when ssh-connect-timeout
                  (concat "  ConnectTimeout " ssh-connect-timeout "\n"))
                (when ssh-control-master
                  (concat "  ControlMaster " ssh-control-master "\n"))
                (when ssh-control-path
                  (concat "  ControlPath " ssh-control-path "\n"))
                (when ssh-control-persist
                  (concat "  ControlPersist " ssh-control-persist "\n"))
                (when ssh-dynamic-forward
                  (concat "  DynamicForward " ssh-dynamic-forward "\n"))
                (when ssh-enable-ssh-keysign
                  (concat "  EnableSSHKeysign " ssh-enable-ssh-keysign "\n"))
                (when ssh-escape-char
                  (concat "  EscapeChar " ssh-escape-char "\n"))
                (when ssh-exit-on-forward-failure
                  (concat "  ExitOnForwardFailure " ssh-exit-on-forward-failure "\n"))
                (when ssh-fingerprint-hash
                  (concat "  FingerprintHash " ssh-fingerprint-hash "\n"))
                (when ssh-forward-agent
                  (concat "  ForwardAgent " ssh-forward-agent "\n"))
                (when ssh-forward-x11
                  (concat "  ForwardX11 " ssh-forward-x11 "\n"))
                (when ssh-forward-x11-timeout
                  (concat "  ForwardX11Timeout " ssh-forward-x11-timeout "\n"))
                (when ssh-forward-x11-trusted
                  (concat "  ForwardX11Trusted " ssh-forward-x11-trusted "\n"))
                (when ssh-gateway-ports
                  (concat "  GatewayPorts " ssh-gateway-ports "\n"))
                (when ssh-global-known-hosts-file
                  (concat "  GlobalKnownHostsFile " ssh-global-known-hosts-file "\n"))
                (when ssh-gssapi-auth
                  (concat "  GSSAPIAuthentication " ssh-gssapi-auth "\n"))
                (when ssh-gssapi-delegate-credentials
                  (concat "  GSSAPIDelegateCredentials " ssh-gssapi-delegate-credentials "\n"))
                (when ssh-hash-known-hosts
                  (concat "  HashKnownHosts " ssh-hash-known-hosts "\n"))
                (when ssh-host-based-auth
                  (concat "  HostbasedAuthentication " ssh-host-based-auth "\n"))
                (when ssh-host-based-key-types
                  (concat "  HostbasedKeyTypes " ssh-host-based-key-types "\n"))
                (when ssh-host-key-algos
                  (concat "  HostKeyAlgorithms " ssh-host-key-algos "\n"))
                (when ssh-host-key-alias
                  (concat "  HostKeyAlias " ssh-host-key-alias "\n"))
                (when ssh-hostname
                  (concat "  Hostname " ssh-hostname "\n"))
                (when ssh-identities-only
                  (concat "  IdentitiesOnly " ssh-identities-only "\n"))
                (when ssh-identity-agent
                  (concat "  IdentityAgent " ssh-identity-agent "\n"))
                (when ssh-identity-file
                  (concat "  IdentityFile " ssh-identity-file "\n"))
                contents)
      contents)))

(defun org-ssh-template (contents _info)
  "Transform CONTENTS into SSH config with header."
  (concat org-ssh-header "\n"
          (replace-regexp-in-string "\n\n\n+" "\n\n" contents)))

(defun org-ssh-export-as-config (&optional ASYNC SUBTREEP VISIBLE-ONLY BODY-ONLY EXT-PLIST)
  "Export current buffer to an SSH config buffer.

If narrowing is active in the current buffer, only transcode its
narrowed part.

If a region is active, transcode that region.

A non-nil optional argument ASYNC means the process should happen
asynchronously.  The resulting buffer should be accessible
through the org-export-stack interface.

When optional argument SUBTREEP is non-nil, transcode the
sub-tree at point, extracting information from the headline
properties first.

When optional argument VISIBLE-ONLY is non-nil, don't export
contents of hidden elements.

When optional argument BODY-ONLY is non-nil, only return body
code, without surrounding template.

Optional argument EXT-PLIST, when provided, is a property list
with external parameters overriding Org default settings, but
still inferior to file-local settings."
  (interactive)
  (org-export-to-buffer 'ssh "*Org SSH Export*"
    ASYNC SUBTREEP VISIBLE-ONLY BODY-ONLY EXT-PLIST
    (lambda () (conf-mode))))

(provide 'ox-ssh)
;;; ox-ssh.el ends here
