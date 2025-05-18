;; Identity Provider Verification Contract
;; Validates and manages credential issuers in the federation

(define-data-var admin principal tx-sender)

;; Map of verified identity providers
(define-map identity-providers
  principal
  {
    name: (string-ascii 64),
    verified: bool,
    verification-date: uint,
    domain: (string-ascii 64)
  }
)

;; Public function to register a new identity provider
(define-public (register-provider (provider-principal principal) (name (string-ascii 64)) (domain (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-none (map-get? identity-providers provider-principal)) (err u100))
    (ok (map-set identity-providers
      provider-principal
      {
        name: name,
        verified: false,
        verification-date: u0,
        domain: domain
      }
    ))
  )
)

;; Public function to verify an identity provider
(define-public (verify-provider (provider-principal principal))
  (let ((provider (unwrap! (map-get? identity-providers provider-principal) (err u404))))
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (map-set identity-providers
      provider-principal
      (merge provider {
        verified: true,
        verification-date: block-height
      })
    ))
  )
)

;; Public function to check if a provider is verified
(define-read-only (is-verified-provider (provider-principal principal))
  (default-to false (get verified (map-get? identity-providers provider-principal)))
)

;; Public function to get provider details
(define-read-only (get-provider-details (provider-principal principal))
  (map-get? identity-providers provider-principal)
)

;; Function to transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (var-set admin new-admin))
  )
)
