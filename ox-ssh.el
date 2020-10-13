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
         (ssh-user (org-element-property :SSH_USER headline))
         (ssh-port (org-element-property :SSH_PORT headline))
         (ssh-identity-file (org-element-property :SSH_IDENTITY_FILE headline))
         (ssh-forward-agent (org-element-property :SSH_FORWARD_AGENT headline))
         (ssh-forward-x11 (org-element-property :SSH_FORWARD_X11 headline))
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
         (addr (or ip url)))
    (if addr
        (concat "\nHost " host "\n"
                "  HostName " addr "\n"
                (when ssh-user
                  (concat "  User " ssh-user "\n"))
                (when ssh-port
                  (concat "  Port " ssh-port "\n"))
                (when ssh-identity-file
                  (concat "  IdentityFile " ssh-identity-file "\n"))
                (when ssh-forward-agent
                  (concat "  ForwardAgent " ssh-forward-agent "\n"))
                (when ssh-forward-x11
                  (concat "  ForwardX11 " ssh-forward-x11 "\n"))
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
