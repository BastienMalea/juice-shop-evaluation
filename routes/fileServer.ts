/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import challengeUtils = require('../lib/challengeUtils')

const challenges = require('../data/datacache').challenges

module.exports = function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    // Remove any null bytes or other control characters that could be used to manipulate the file path
    file = file.replace(/[\0]+/g, '')

    // Ensure the file has a valid, allow listed extension after sanitization
    if (isValidExtension(file)) {
      // Proceed to serve the file, ensuring that the path is correctly resolved and does not traverse directories
      const filePath = path.resolve('ftp/', file)
      // Security measure to prevent directory traversal attacks
      if (filePath.startsWith(path.resolve('ftp/'))) {
        res.sendFile(filePath)
      } else {
        res.status(403).send('Access to the requested file path is forbidden.')
      }
    } else {
      res.status(403).send('Invalid file type.')
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
    verifySuccessfulPoisonNullByteExploit(file)
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function isValidExtension (file: string) {
    const allowedExtensions = ['.md', '.pdf']
    const extension = path.extname(file).toLowerCase()
    return allowedExtensions.includes(extension)
  }
}
