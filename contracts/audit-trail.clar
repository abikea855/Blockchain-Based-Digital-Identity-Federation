;; Audit Trail Contract
;; Records identity verification activities

(define-data-var admin principal tx-sender)

;; Map of audit records
(define-map audit-records
  (buff 32) ;; record ID (hash)
  {
    action: (string-ascii 32), ;; "verify", "authenticate", "revoke", etc.
    subject: (buff 32), ;; hashed identifier of the subject
    actor: principal, ;; who performed the action
    domain: (string-ascii 64),
    timestamp: uint,
    details: (string-ascii 256)
  }
)

;; Public function to record an audit event
(define-public (record-audit-event
  (record-id (buff 32))
  (action (string-ascii 32))
  (subject (buff 32))
  (domain (string-ascii 64))
  (details (string-ascii 256)))
  (begin
    (asserts! (is-none (map-get? audit-records record-id)) (err u100))
    (ok (map-set audit-records
      record-id
      {
        action: action,
        subject: subject,
        actor: tx-sender,
        domain: domain,
        timestamp: block-height,
        details: details
      }
    ))
  )
)

;; Read-only function to get audit record
(define-read-only (get-audit-record (record-id (buff 32)))
  (map-get? audit-records record-id)
)

;; Function to transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (var-set admin new-admin))
  )
)
