/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const safeFile = path.basename(file)

    if (file === safeFile && !file.includes('/') && !file.includes('\\')) {
      res.sendFile(safeFile, { root: path.resolve('encryptionkeys') })
    } else {
      res.status(403)
      next(new Error('File names cannot contain path separators!'))
    }
  }
}
