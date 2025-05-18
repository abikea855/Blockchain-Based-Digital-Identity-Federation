;; Authentication Protocol Contract
;; Manages secure login processes across domains

(define-data-var admin principal tx-sender)

;; Map of authentication sessions
(define-map auth-sessions
  (buff 32) ;; session ID (hash)
  {
    user-id: (buff 32), ;; hashed user identifier
    provider: principal,
    domain: (string-ascii 64),
    created-at: uint,
    expires-at: uint,
    status: (string-ascii 16) ;; "pending", "authenticated", "rejected", "expired"
  }
)

;; Map of user authentication records
(define-map user-auth-records
  (buff 32) ;; hashed user identifier
  {
    last-auth: uint,
    auth-count: uint,
    providers: (list 10 principal)
  }
)

;; Public function to initiate authentication session
(define-public (initiate-auth-session
  (session-id (buff 32))
  (user-id (buff 32))
  (domain (string-ascii 64))
  (expiration uint))
  (begin
    (asserts! (is-none (map-get? auth-sessions session-id)) (err u100))
    (asserts! (> expiration block-height) (err u102))
    (ok (map-set auth-sessions
      session-id
      {
        user-id: user-id,
        provider: tx-sender,
        domain: domain,
        created-at: block-height,
        expires-at: expiration,
        status: "pending"
      }
    ))
  )
)

;; Public function to complete authentication
(define-public (complete-authentication (session-id (buff 32)) (success bool))
  (let (
    (session (unwrap! (map-get? auth-sessions session-id) (err u404)))
    (user-record (default-to
      { last-auth: u0, auth-count: u0, providers: (list) }
      (map-get? user-auth-records (get user-id session))
    ))
  )
    (asserts! (is-eq (get provider session) tx-sender) (err u403))
    (asserts! (is-eq (get status session) "pending") (err u401))
    (asserts! (<= block-height (get expires-at session)) (err u410))

    ;; Update session status
    (map-set auth-sessions
      session-id
      (merge session { status: (if success "authenticated" "rejected") })
    )

    ;; Update user record if authentication was successful
    (if success
      (map-set user-auth-records
        (get user-id session)
        {
          last-auth: block-height,
          auth-count: (+ (get auth-count user-record) u1),
          providers: (unwrap! (as-max-len?
                               (append (get providers user-record) tx-sender)
                               u10)
                             (err u500))
        }
      )
      true
    )

    (ok success)
  )
)

;; Read-only function to check authentication status
(define-read-only (get-auth-status (session-id (buff 32)))
  (let ((session (map-get? auth-sessions session-id)))
    (if (is-some session)
      (let ((session-data (unwrap! session (err u404))))
        (if (> (get expires-at session-data) block-height)
          (ok (get status session-data))
          (ok "expired")
        )
      )
      (err u404)
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
