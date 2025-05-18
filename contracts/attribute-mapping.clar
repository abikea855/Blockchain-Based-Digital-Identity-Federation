;; Attribute Mapping Contract
;; Standardizes identity claims across different systems

(define-data-var admin principal tx-sender)

;; Map of standard attribute definitions
(define-map standard-attributes
  (string-ascii 64) ;; attribute name
  {
    description: (string-ascii 256),
    data-type: (string-ascii 16), ;; "string", "uint", "bool", etc.
    created-at: uint
  }
)

;; Map of attribute mappings from domain-specific to standard
(define-map attribute-mappings
  {
    domain: (string-ascii 64),
    domain-attribute: (string-ascii 64)
  }
  {
    standard-attribute: (string-ascii 64),
    transformation: (string-ascii 128), ;; Optional transformation rule
    created-at: uint
  }
)

;; Public function to define a standard attribute
(define-public (define-standard-attribute
  (attribute-name (string-ascii 64))
  (description (string-ascii 256))
  (data-type (string-ascii 16)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-none (map-get? standard-attributes attribute-name)) (err u100))
    (ok (map-set standard-attributes
      attribute-name
      {
        description: description,
        data-type: data-type,
        created-at: block-height
      }
    ))
  )
)

;; Public function to create attribute mapping
(define-public (create-attribute-mapping
  (domain (string-ascii 64))
  (domain-attribute (string-ascii 64))
  (standard-attribute (string-ascii 64))
  (transformation (string-ascii 128)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-some (map-get? standard-attributes standard-attribute)) (err u404))
    (ok (map-set attribute-mappings
      {
        domain: domain,
        domain-attribute: domain-attribute
      }
      {
        standard-attribute: standard-attribute,
        transformation: transformation,
        created-at: block-height
      }
    ))
  )
)

;; Read-only function to get standard attribute definition
(define-read-only (get-standard-attribute (attribute-name (string-ascii 64)))
  (map-get? standard-attributes attribute-name)
)

;; Read-only function to get attribute mapping
(define-read-only (get-attribute-mapping (domain (string-ascii 64)) (domain-attribute (string-ascii 64)))
  (map-get? attribute-mappings { domain: domain, domain-attribute: domain-attribute })
)

;; Function to transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (var-set admin new-admin))
  )
)
