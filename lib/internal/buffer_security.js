/**
 * Buffer Path Traversal Vulnerability Analysis and Fix
 * CVE-2024-21896: Path traversal by monkey-patching Buffer internals
 * 
 * This file demonstrates the vulnerability and implements a potential fix
 * at the Node.js core level to prevent Buffer prototype manipulation
 * from affecting filesystem security.
 */

'use strict';

/**
 * Buffer Path Traversal Vulnerability Analysis and Fix
 * CVE-2024-21896: Path traversal by monkey-patching Buffer internals
 * 
 * This file demonstrates the vulnerability and implements a potential fix
 * at the Node.js core level to prevent Buffer prototype manipulation
 * from affecting filesystem security.
 */

// Store original Buffer methods before they can be monkey-patched
const originalBufferMethods = {
  utf8Write: Buffer.prototype.utf8Write,
  toString: Buffer.prototype.toString,
  from: Buffer.from,
};

// Freeze the original methods to prevent modification
Object.freeze(originalBufferMethods);

/**
 * Secure Buffer operations that use original methods
 * This prevents monkey-patching attacks on Buffer prototypes
 */
class SecureBuffer {
  /**
   * Securely convert a Buffer to string using original toString method
   * @param {Buffer} buffer - The buffer to convert
   * @param {string} encoding - The encoding to use
   * @returns {string} The string representation
   */
  static secureToString(buffer, encoding = 'utf8') {
    if (!(buffer instanceof Buffer)) {
      throw new TypeError('Expected a Buffer instance');
    }
    
    // Use the original toString method directly
    return originalBufferMethods.toString.call(buffer, encoding);
  }

  /**
   * Securely write UTF-8 string to buffer using original method
   * @param {Buffer} buffer - The target buffer
   * @param {string} string - The string to write
   * @param {number} offset - The offset to start writing
   * @param {number} length - The maximum length to write
   * @returns {number} The number of bytes written
   */
  static secureUtf8Write(buffer, string, offset = 0, length = buffer.byteLength - offset) {
    if (!(buffer instanceof Buffer)) {
      throw new TypeError('Expected a Buffer instance');
    }
    
    // Use the original utf8Write method directly
    return originalBufferMethods.utf8Write.call(buffer, string, offset, length);
  }

  /**
   * Securely create a Buffer using original Buffer.from method
   * @param {*} source - The source to create buffer from
   * @param {string} encoding - The encoding if source is string
   * @returns {Buffer} The created buffer
   */
  static secureFrom(source, encoding) {
    // Use the original Buffer.from method directly
    return originalBufferMethods.from.call(Buffer, source, encoding);
  }

  static get originalBufferMethods() {
    return originalBufferMethods;
  }
}

/**
 * Enhanced path validation that's resistant to Buffer monkey-patching
 */
class SecurePathValidator {
  constructor(allowedBasePath) {
    this.allowedBasePath = require('path').resolve(allowedBasePath);
  }

  /**
   * Validate a path using secure Buffer operations
   * @param {string|Buffer} inputPath - The path to validate
   * @returns {string} The validated path
   * @throws {Error} If path is invalid or traverses outside allowed directory
   */
  validatePath(inputPath) {
    let pathString;
    
    if (Buffer.isBuffer(inputPath)) {
      // Use secure toString to prevent monkey-patching
      pathString = SecureBuffer.secureToString(inputPath);
    } else if (typeof inputPath === 'string') {
      pathString = inputPath;
    } else {
      throw new TypeError('Path must be a string or Buffer');
    }

    const path = require('path');
    
    // Resolve the path relative to the allowed base
    const resolvedPath = path.resolve(this.allowedBasePath, pathString);
    
    // Check if the resolved path is within the allowed directory
    if (!resolvedPath.startsWith(this.allowedBasePath)) {
      throw new Error(`Path traversal detected: ${pathString}`);
    }

    // Additional validation: create a buffer and check it again
    // This prevents attacks that might manipulate the path after initial validation
    const pathBuffer = SecureBuffer.secureFrom(resolvedPath);
    const finalPath = SecureBuffer.secureToString(pathBuffer);
    
    if (!finalPath.startsWith(this.allowedBasePath)) {
      throw new Error(`Buffer manipulation detected: ${pathString}`);
    }

    return finalPath;
  }
}

/**
 * Core Node.js fix concept: Freeze Buffer prototype methods
 * This should be implemented in the Node.js core to prevent monkey-patching
 */
function freezeBufferPrototypeMethods() {
  // Define non-configurable, non-writable properties for critical methods
  Object.defineProperty(Buffer.prototype, 'utf8Write', {
    value: originalBufferMethods.utf8Write,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  Object.defineProperty(Buffer.prototype, 'toString', {
    value: originalBufferMethods.toString,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  Object.defineProperty(Buffer, 'from', {
    value: originalBufferMethods.from,
    writable: false,
    configurable: false,
    enumerable: false,
  });
}

// Export for testing
module.exports = {
  SecureBuffer,
  SecurePathValidator,
  freezeBufferPrototypeMethods,
  originalBufferMethods,
};