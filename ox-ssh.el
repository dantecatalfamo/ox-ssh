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
         (ssh-forward (org-element-property :SSH_FORWARD headline))
         (ssh-port (org-element-property :SSH_PORT headline))
         (user (org-element-property :SSH_USER headline))
         (addr (or ip url)))
    (if addr
        (concat "\nHost " host "\n"
                "  HostName " addr "\n"
                (when ssh-forward
                  "  ForwardAgent yes\n")
                (when ssh-port
                  (concat "  Port " ssh-port "\n"))
                (when user
                  (concat "  User " user "\n"))
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
