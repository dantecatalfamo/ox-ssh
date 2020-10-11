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
                             (template . org-ssh-template)))

(defun org-ssh-headline (headline _contents _info)
  "Transform HEADLINE into SSH config host."
  (let ((url (org-element-property :URL headline))
        (ip (org-element-property :IP headline))
        (host (car (org-element-property :title headline)))
        (ssh-forward (org-element-property :SSH_FORWARD headline))
        (ssh-port (org-element-property :SSH_PORT headline))
        (user (org-element-property :SSH_USER headline)))
    (when-let (addr (or ip url))
      (concat "Host " host "\n"
              "  HostName " addr "\n"
              (when ssh-forward
                "  ForwardAgent yes\n")
              (when ssh-port
                (concat "  Port " ssh-port "\n"))
              (when user
                (concat "  User " user "\n"))
              "\n"))))

(defun org-ssh-template (contents _info)
  "Transform CONTENTS into SSH config with header."
  (concat org-ssh-header "\n"
          contents))

(provide 'ox-ssh)
;;; ox-ssh.el ends here
