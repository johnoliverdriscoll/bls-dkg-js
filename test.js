'use strict'
const {
  generatePolynomial,
  secretShares,
  publicShare,
  mergeSecretShares,
  mergePublicShares,
  mergeSignatures,
  sign,
  verify,
} = require('.')

{(async function() {

  // Threshold.
  const m = 2
  // Number of signers.
  const n = 3

  // User generates their polynomial and secret/public shares.
  const userPolynomial = generatePolynomial(m)
  const userSecretShares = secretShares(userPolynomial, n)
  const userPublicShare = publicShare(userPolynomial)

  // User encrypts userSecretShares[0] to their password to get enc(userSecretShares[0]).
  // User sends userSecretShares[1] to backup key provider and requests a backup key.

  // Backup key provider generates their polynomial and secret/public shares.
  const backupPolynomial = generatePolynomial(m)
  const backupSecretShares = secretShares(backupPolynomial, n)
  const backupPublicShare = publicShare(backupPolynomial)

  // Backup key provider stores userSecretShares[1] and backupSecretShares[1].
  // Backup key provider returns backupSecretShares[0,2] and backupPublicShare to user.

  // User encrypts backupSecretShares[0] to their password to get enc(backupSecretShares[0]).
  // User sends enc(userSecretShares[0]), enc(backupSecretShares[0]), userSecretShares[2],
  // userPublicShare, and backupPublicShare to wallet service and requests a new wallet.

  // Wallet service generates their polynomial and secret/public shares.
  const walletPolynomial = generatePolynomial(m)
  const walletSecretShares = secretShares(walletPolynomial, n)
  const walletPublicShare = publicShare(walletPolynomial)

  // Wallet service computes the common public key (wallet address) using userPublicShare,
  // backupPublicShare, and walletPublicShare.
  const commonPub = mergePublicShares([userPublicShare, backupPublicShare, walletPublicShare])

  // Wallet service computes their signing key.
  const walletKey = mergeSecretShares([userSecretShares[2], backupSecretShares[2], walletSecretShares[2]])

  // Wallet service stores commonPub, walletKey, enc(userSecretShares[0]),
  // enc(backupSecretShares[0]), and walletSecretShares[0].
  // Wallet service sends commonPub and walletSecretShares[1] to backup key provider.

  // Backup key provider computes their signing key.
  const backupKey = mergeSecretShares([userSecretShares[1], backupSecretShares[1], walletSecretShares[1]])

  // Backup key provider stores commonPub and backupKey.
  // Backup key provider can delete userSecretShares[1] and backupSecretShares[1].

  // Wallet service returns walletSecretShares[0] and commonPub to user.

  // User computes their signing key for their backup key card.
  let userKey = mergeSecretShares([userSecretShares[0], backupSecretShares[0], walletSecretShares[0]])

  // User encrypts their signing key to their password for their backup key card.

  // When user wants to spend, they request their shares from wallet service.
  // Wallet service sends enc(userSecretShares[0]), enc(backupSecretShares[0]),
  // and walletSecretShares[0] to user.

  // User decrypts enc(userSecretShares[0]) and enc(backupSecretShares[0]).

  // User computes their signing key.
  userKey = mergeSecretShares([userSecretShares[0], backupSecretShares[0], walletSecretShares[0]])

  // User creates a transaction and gets its signing hash.
  const message = 'Hello'

  // User signs the transaction using their signing key.
  const userSig = await sign(message, userKey)

  // User sends transaction and userSig to wallet service.

  // Wallet service signs the transaction using their signing key.
  const walletSig = await sign(message, walletKey)

  // Wallet service combines the signature shares to get the common signature.
  const userWalletSig = mergeSignatures({
    1: userSig,
    3: walletSig,
  })

  // Wallet service verifies the common signature against the common public key.
  if (!await verify(userWalletSig, message, commonPub)) {
    throw new Error('Could not verify user + wallet service signature')
  }

  // Wallet service applies the common signature to the transaction and broadcasts it to
  // the network.

  // Alternatively, if the user loses their password, the backup key provider can
  // be the final signer.
  const backupSig = await sign(message, backupKey)
  const backupWalletSig = mergeSignatures({
    2: backupSig,
    3: walletSig,
  })
  if (!await verify(backupWalletSig, message, commonPub)) {
    throw new Error('Could not verify backup key provider + wallet service signature')
  }

  // If wallet service should go offline, the user and backup key provider can recover funds.
  const userBackupSig = mergeSignatures({
    1: userSig,
    2: backupSig,
  })
  if (!await verify(userBackupSig, message, commonPub)) {
    throw new Error('Could not verify backup key provider + wallet service signature')
  }

  console.log('Success')

})()}
