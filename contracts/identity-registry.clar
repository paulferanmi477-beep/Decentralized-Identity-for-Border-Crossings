(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-DUPLICATE-IDENTITY u101)
(define-constant ERR-INVALID-HASH u102)
(define-constant ERR-INVALID-PUBLIC-KEY u103)
(define-constant ERR-INVALID-NAME u104)
(define-constant ERR-INVALID-BIOMETRIC u105)
(define-constant ERR-INVALID-TIMESTAMP u106)
(define-constant ERR-IDENTITY-NOT-FOUND u107)
(define-constant ERR-INVALID-RECOVERY-CONTACTS u108)
(define-constant ERR-RECOVERY-ALREADY-INITIATED u109)
(define-constant ERR-RECOVERY-NOT-INITIATED u110)
(define-constant ERR-INVALID-APPROVAL-COUNT u111)
(define-constant ERR-INVALID-STATUS u112)
(define-constant ERR-INVALID-UPDATE-PARAM u113)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u114)
(define-constant ERR-MAX-IDENTITIES-EXCEEDED u115)

(define-data-var next-identity-id uint u0)
(define-data-var max-identities uint u1000000)
(define-data-var authority-contract (optional principal) none)

(define-map identities
  uint
  { identity-hash: (buff 32),
    public-key: (buff 33),
    name: (string-utf8 100),
    biometric-hash: (buff 32),
    timestamp: uint,
    creator: principal,
    status: bool,
    recovery-contacts: (list 5 principal),
    recovery-threshold: uint,
    recovery-initiated: bool,
    recovery-approvals: (list 5 principal) })

(define-map identities-by-hash
  (buff 32)
  uint)

(define-map identity-updates
  uint
  { update-name: (string-utf8 100),
    update-timestamp: uint,
    updater: principal })

(define-read-only (get-identity (id uint))
  (map-get? identities id))

(define-read-only (get-identity-by-hash (hash (buff 32)))
  (match (map-get? identities-by-hash hash)
    id (map-get? identities id)
    none))

(define-read-only (get-identity-updates (id uint))
  (map-get? identity-updates id))

(define-read-only (is-identity-registered (hash (buff 32)))
  (is-some (map-get? identities-by-hash hash)))

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-HASH)))

(define-private (validate-public-key (key (buff 33)))
  (if (is-eq (len key) u33)
      (ok true)
      (err ERR-INVALID-PUBLIC-KEY)))

(define-private (validate-name (name (string-utf8 100)))
  (if (and (> (len name) u0) (<= (len name) u100))
      (ok true)
      (err ERR-INVALID-NAME)))

(define-private (validate-biometric (bio (buff 32)))
  (if (is-eq (len bio) u32)
      (ok true)
      (err ERR-INVALID-BIOMETRIC)))

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP)))

(define-private (validate-recovery-contacts (contacts (list 5 principal)))
  (if (and (>= (len contacts) u2) (<= (len contacts) u5))
      (ok true)
      (err ERR-INVALID-RECOVERY-CONTACTS)))

(define-private (validate-recovery-threshold (threshold uint) (contacts (list 5 principal)))
  (if (and (> threshold u0) (<= threshold (len contacts)))
      (ok true)
      (err ERR-INVALID-APPROVAL-COUNT)))

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (asserts! (not (is-eq contract-principal 'SP000000000000000000002Q6VF78)) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-none (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set authority-contract (some contract-principal))
    (ok true)))

(define-public (register-identity
  (identity-hash (buff 32))
  (public-key (buff 33))
  (name (string-utf8 100))
  (biometric-hash (buff 32))
  (recovery-contacts (list 5 principal))
  (recovery-threshold uint))
  (let ((id (var-get next-identity-id))
        (max-ids (var-get max-identities))
        (authority (var-get authority-contract)))
    (asserts! (< id max-ids) (err ERR-MAX-IDENTITIES-EXCEEDED))
    (try! (validate-hash identity-hash))
    (try! (validate-public-key public-key))
    (try! (validate-name name))
    (try! (validate-biometric biometric-hash))
    (try! (validate-recovery-contacts recovery-contacts))
    (try! (validate-recovery-threshold recovery-threshold recovery-contacts))
    (asserts! (is-none (map-get? identities-by-hash identity-hash)) (err ERR-DUPLICATE-IDENTITY))
    (asserts! (is-some authority) (err ERR-AUTHORITY-NOT-VERIFIED))
    (map-set identities id
      { identity-hash: identity-hash,
        public-key: public-key,
        name: name,
        biometric-hash: biometric-hash,
        timestamp: block-height,
        creator: tx-sender,
        status: true,
        recovery-contacts: recovery-contacts,
        recovery-threshold: recovery-threshold,
        recovery-initiated: false,
        recovery-approvals: (list ) })
    (map-set identities-by-hash identity-hash id)
    (var-set next-identity-id (+ id u1))
    (print { event: "identity-registered", id: id })
    (ok id)))

(define-public (update-identity
  (id uint)
  (new-name (string-utf8 100)))
  (let ((identity (map-get? identities id)))
    (match identity
      id-data
      (begin
        (asserts! (is-eq (get creator id-data) tx-sender) (err ERR-NOT-AUTHORIZED))
        (try! (validate-name new-name))
        (map-set identities id
          { identity-hash: (get identity-hash id-data),
            public-key: (get public-key id-data),
            name: new-name,
            biometric-hash: (get biometric-hash id-data),
            timestamp: block-height,
            creator: (get creator id-data),
            status: (get status id-data),
            recovery-contacts: (get recovery-contacts id-data),
            recovery-threshold: (get recovery-threshold id-data),
            recovery-initiated: (get recovery-initiated id-data),
            recovery-approvals: (get recovery-approvals id-data) })
        (map-set identity-updates id
          { update-name: new-name,
            update-timestamp: block-height,
            updater: tx-sender })
        (print { event: "identity-updated", id: id })
        (ok true))
      (err ERR-IDENTITY-NOT-FOUND))))

(define-public (initiate-recovery
  (id uint))
  (let ((identity (map-get? identities id)))
    (match identity
      id-data
      (begin
        (asserts! (is-eq (get creator id-data) tx-sender) (err ERR-NOT-AUTHORIZED))
        (asserts! (not (get recovery-initiated id-data)) (err ERR-RECOVERY-ALREADY-INITIATED))
        (map-set identities id
          { identity-hash: (get identity-hash id-data),
            public-key: (get public-key id-data),
            name: (get name id-data),
            biometric-hash: (get biometric-hash id-data),
            timestamp: (get timestamp id-data),
            creator: (get creator id-data),
            status: (get status id-data),
            recovery-contacts: (get recovery-contacts id-data),
            recovery-threshold: (get recovery-threshold id-data),
            recovery-initiated: true,
            recovery-approvals: (list ) })
        (print { event: "recovery-initiated", id: id })
        (ok true))
      (err ERR-IDENTITY-NOT-FOUND))))

(define-public (approve-recovery
  (id uint))
  (let ((identity (map-get? identities id)))
    (match identity
      id-data
      (begin
        (asserts! (get recovery-initiated id-data) (err ERR-RECOVERY-NOT-INITIATED))
        (asserts! (is-some (index-of (get recovery-contacts id-data) tx-sender)) (err ERR-NOT-AUTHORIZED))
        (let ((approvals (get recovery-approvals id-data))
              (new-approvals (unwrap! (as-max-len? (append approvals tx-sender) u5) (err ERR-INVALID-APPROVAL-COUNT))))
          (map-set identities id
            { identity-hash: (get identity-hash id-data),
              public-key: (get public-key id-data),
              name: (get name id-data),
              biometric-hash: (get biometric-hash id-data),
              timestamp: (get timestamp id-data),
              creator: (get creator id-data),
              status: (get status id-data),
              recovery-contacts: (get recovery-contacts id-data),
              recovery-threshold: (get recovery-threshold id-data),
              recovery-initiated: (get recovery-initiated id-data),
              recovery-approvals: new-approvals })
          (print { event: "recovery-approved", id: id, approver: tx-sender })
          (ok true)))
      (err ERR-IDENTITY-NOT-FOUND))))

(define-public (complete-recovery
  (id uint)
  (new-public-key (buff 33)))
  (let ((identity (map-get? identities id)))
    (match identity
      id-data
      (begin
        (asserts! (get recovery-initiated id-data) (err ERR-RECOVERY-NOT-INITIATED))
        (asserts! (>= (len (get recovery-approvals id-data)) (get recovery-threshold id-data)) (err ERR-INVALID-APPROVAL-COUNT))
        (try! (validate-public-key new-public-key))
        (map-set identities id
          { identity-hash: (get identity-hash id-data),
            public-key: new-public-key,
            name: (get name id-data),
            biometric-hash: (get biometric-hash id-data),
            timestamp: block-height,
            creator: tx-sender,
            status: (get status id-data),
            recovery-contacts: (get recovery-contacts id-data),
            recovery-threshold: (get recovery-threshold id-data),
            recovery-initiated: false,
            recovery-approvals: (list ) })
        (print { event: "recovery-completed", id: id })
        (ok true))
      (err ERR-IDENTITY-NOT-FOUND))))