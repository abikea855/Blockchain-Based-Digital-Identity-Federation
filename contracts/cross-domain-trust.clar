;; Cross-Domain Trust Contract
;; Manages trust relationships between different identity systems

(define-data-var admin principal tx-sender)

;; Map of trust relationships between domains
(define-map trust-relationships
  { domain-a: (string-ascii 64), domain-b: (string-ascii 64) }
  {
    trust-level: uint,
    established-at: uint,
    expiration: uint
  }
)

;; Trust levels:
;; 0 = No trust
;; 1 = Basic trust (identity only)
;; 2 = Medium trust (identity + basic attributes)
;; 3 = Full trust (all attributes)

;; Public function to establish trust between domains
(define-public (establish-trust
  (domain-a (string-ascii 64))
  (domain-b (string-ascii 64))
  (trust-level uint)
  (expiration uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (<= trust-level u3) (err u101))
    (asserts! (> expiration block-height) (err u102))
    (ok (map-set trust-relationships
      { domain-a: domain-a, domain-b: domain-b }
      {
        trust-level: trust-level,
        established-at: block-height,
        expiration: expiration
      }
    ))
  )
)

;; Public function to revoke trust between domains
(define-public (revoke-trust (domain-a (string-ascii 64)) (domain-b (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-some (map-get? trust-relationships { domain-a: domain-a, domain-b: domain-b })) (err u404))
    (ok (map-delete trust-relationships { domain-a: domain-a, domain-b: domain-b }))
  )
)

;; Read-only function to check trust level between domains
(define-read-only (get-trust-level (domain-a (string-ascii 64)) (domain-b (string-ascii 64)))
  (let ((relationship (map-get? trust-relationships { domain-a: domain-a, domain-b: domain-b })))
    (if (is-some relationship)
      (let ((trust-data (unwrap! relationship (err u404))))
        (if (> (get expiration trust-data) block-height)
          (ok (get trust-level trust-data))
          (ok u0) ;; Trust expired
        )
      )
      (ok u0) ;; No trust relationship
    )
  )
)

;; Function to transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (var-set admin new-admin))
  )
)
