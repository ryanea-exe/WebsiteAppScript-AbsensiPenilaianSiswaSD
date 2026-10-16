/**
 * PHASE 2 — SECURITY & AUTHENTICATION BENCHMARK SUITE
 * Proyek: Sistem Absensi dan Penilaian Siswa SD
 * Berkas: phase2_security_benchmark.gs
 *
 * Tujuan:
 * 1. Mengukur waktu eksekusi komputasi PBKDF2-HMAC-SHA256 vs Repeated HMAC-SHA256 pada V8.
 * 2. Menguji karakteristik keacakan dan keunikan token sesi (Utilities.getUuid()).
 * 3. Menguji logika otorisasi server-side Zero-Trust, session expiry, dan brute-force throttling.
 *
 * Catatan Runtime:
 * Berkas ini dapat dijalankan secara langsung di Google Apps Script V8 (fungsi: runPhase2Benchmark)
 * maupun di runtime Node.js V8 lokal untuk verifikasi independen (node phase2_security_benchmark.gs).
 */

// ============================================================================
// 1. RUNTIME SHIM (Hanya aktif saat dieksekusi di luar Google Apps Script)
// ============================================================================
/* global Utilities, PropertiesService, Logger */
if (typeof Utilities === 'undefined') {
  const nodeCrypto = require('crypto');
  global.Utilities = {
    DigestAlgorithm: { SHA_256: 'SHA_256' },
    computeDigest: function(algo, value) {
      const hash = nodeCrypto.createHash('sha256').update(value, 'utf8').digest();
      const signed = [];
      for (let i = 0; i < hash.length; i++) {
        let b = hash[i];
        if (b > 127) b -= 256;
        signed.push(b);
      }
      return signed;
    },
    computeHmacSha256Signature: function(value, key) {
      const vBuf = typeof value === 'string' 
        ? Buffer.from(value, 'utf8') 
        : Buffer.from(value.map(b => b < 0 ? b + 256 : b));
      const kBuf = typeof key === 'string' 
        ? Buffer.from(key, 'utf8') 
        : Buffer.from(key.map(b => b < 0 ? b + 256 : b));
      const hmac = nodeCrypto.createHmac('sha256', kBuf).update(vBuf).digest();
      const signed = [];
      for (let i = 0; i < hmac.length; i++) {
        let b = hmac[i];
        if (b > 127) b -= 256;
        signed.push(b);
      }
      return signed;
    },
    getUuid: function() {
      return nodeCrypto.randomUUID();
    }
  };

  global.Logger = {
    log: function(msg) {
      console.log(msg);
    }
  };
}

// ============================================================================
// 2. HELPER KRIPTOGRAFI DASAR
// ============================================================================

/**
 * Mengonversi array signed byte Google Apps Script ke string Hexadesimal.
 */
function bytesToHex_(bytes) {
  return bytes.map(function(b) {
    return (b < 0 ? b + 256 : b).toString(16).padStart(2, '0');
  }).join('');
}

/**
 * Mengonversi string UTF-8 ke array signed byte Google Apps Script.
 */
function stringToSignedBytes_(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 128) {
      bytes.push(code > 127 ? code - 256 : code);
    } else {
      // Sederhana untuk karakter ASCII umum
      bytes.push(code & 0xFF);
    }
  }
  return bytes;
}

/**
 * Pembandingan dua string hash secara Constant-Time untuk mencegah Timing Attack.
 */
function constantTimeEquals_(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Menghasilkan salt acak 16-byte berbasis keacakan platform.
 */
function generateSalt16Bytes_() {
  const uuid1 = Utilities.getUuid().replace(/-/g, '');
  return uuid1.substring(0, 32); // 32 karakter hex = 16 bytes
}

/**
 * Menghitung SHA-256 hash dari token string (untuk token_hash).
 */
function hashTokenSha256_(token) {
  const digestBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, token);
  return bytesToHex_(digestBytes);
}

// ============================================================================
// 3. IMPLEMENTASI KANDIDAT DERIVASI PASSWORD
// ============================================================================

/**
 * KANDIDAT A: PBKDF2-HMAC-SHA256 Standar (RFC 2898 / RFC 8018)
 * Menghasilkan kunci derivasi 256-bit (32 bytes).
 */
function pbkdf2HmacSha256_(password, saltHex, iterations, pepper) {
  const effectivePassword = password + (pepper || '');
  const saltBytes = [];
  for (let i = 0; i < saltHex.length; i += 2) {
    let b = parseInt(saltHex.substr(i, 2), 16);
    if (b > 127) b -= 256;
    saltBytes.push(b);
  }
  
  // S || INT_32_BE(1)
  const initialValue = saltBytes.concat([0, 0, 0, 1]);
  
  // U_1 = PRF(password, salt || 1)
  let u = Utilities.computeHmacSha256Signature(initialValue, effectivePassword);
  const dk = u.slice(); // Akumulator XOR
  
  // U_2 ... U_c
  for (let i = 2; i <= iterations; i++) {
    u = Utilities.computeHmacSha256Signature(u, effectivePassword);
    for (let k = 0; k < 32; k++) {
      dk[k] ^= u[k];
    }
  }
  
  return bytesToHex_(dk);
}

/**
 * KANDIDAT B: Repeated HMAC-SHA256 (Loop Hash Berantai Ad-Hoc)
 * Bukan standar RFC PBKDF2, tidak memiliki akumulasi XOR.
 */
function repeatedHmacSha256_(password, saltHex, iterations, pepper) {
  const effectiveKey = password + (pepper || '');
  let currentHash = Utilities.computeHmacSha256Signature(saltHex, effectiveKey);
  
  for (let i = 2; i <= iterations; i++) {
    currentHash = Utilities.computeHmacSha256Signature(currentHash, effectiveKey);
  }
  
  return bytesToHex_(currentHash);
}

/**
 * KANDIDAT C (Baseline Komparasi): Single HMAC-SHA256 (1 iterasi)
 * Menunjukkan mengapa 1 iterasi tidak dapat diterima untuk password hashing.
 */
function singleHmacSha256_(password, saltHex, pepper) {
  const signature = Utilities.computeHmacSha256Signature(saltHex, password + (pepper || ''));
  return bytesToHex_(signature);
}

// ============================================================================
// 4. MODUL SIMULASI OTORISASI BACKEND ZERO-TRUST
// ============================================================================

const MockDatabase = {
  sessions: {},
  users: {
    'USR-ADM-01': { pengguna_id: 'USR-ADM-01', username: 'admin1', peran: 'admin', status: 'aktif', failed_attempts: 0, locked_until: 0 },
    'USR-GUR-01': { pengguna_id: 'USR-GUR-01', username: 'guru1', peran: 'guru', status: 'aktif', failed_attempts: 0, locked_until: 0 },
    'USR-GUR-02': { pengguna_id: 'USR-GUR-02', username: 'guru2', peran: 'guru', status: 'nonaktif', failed_attempts: 0, locked_until: 0 }
  },
  assignments: [
    { pengguna_id: 'USR-GUR-01', kelas_id: 'KLS-01', mapel_id: 'MPL-001', peran_penugasan: 'wali_kelas' }
  ]
};

function issueSession_(pengguna_id, durationHours) {
  const rawToken = Utilities.getUuid();
  const tokenHash = hashTokenSha256_(rawToken);
  const now = Date.now();
  const expiredAt = new Date(now + (durationHours || 8) * 3600 * 1000).toISOString();
  
  MockDatabase.sessions[tokenHash] = {
    sesi_id: 'SES-' + Utilities.getUuid().substring(0, 8),
    pengguna_id: pengguna_id,
    token_hash: tokenHash,
    expired_at: expiredAt,
    created_at: new Date(now).toISOString()
  };
  
  return { rawToken: rawToken, tokenHash: tokenHash, expired_at: expiredAt };
}

function revokeSession_(rawToken) {
  const tokenHash = hashTokenSha256_(rawToken);
  if (MockDatabase.sessions[tokenHash]) {
    delete MockDatabase.sessions[tokenHash];
    return true;
  }
  return false;
}

function validateSessionMiddleware_(rawToken) {
  if (!rawToken || typeof rawToken !== 'string') {
    return { success: false, code: 401, error: 'UNAUTHORIZED: Token sesi tidak disertakan.' };
  }
  const tokenHash = hashTokenSha256_(rawToken);
  const session = MockDatabase.sessions[tokenHash];
  if (!session) {
    return { success: false, code: 401, error: 'UNAUTHORIZED: Sesi tidak ditemukan atau telah dicabut.' };
  }
  
  const nowIso = new Date().toISOString();
  if (session.expired_at < nowIso) {
    delete MockDatabase.sessions[tokenHash];
    return { success: false, code: 401, error: 'UNAUTHORIZED: Sesi telah kedaluwarsa (expired_at < now).' };
  }
  
  const user = MockDatabase.users[session.pengguna_id];
  if (!user || user.status !== 'aktif') {
    return { success: false, code: 403, error: 'FORBIDDEN: Akun pengguna dinonaktifkan atau tidak ditemukan.' };
  }
  
  return { success: true, user: user, session: session };
}

function verifyAuthorizationGuard_(authContext, requiredRole, kelasId, mapelId) {
  if (!authContext.success) return authContext;
  const user = authContext.user;
  
  // Administrator memiliki hak akses lintas kelas
  if (user.peran === 'admin') {
    return { success: true, authorized: true, role: 'admin' };
  }
  
  // Verifikasi kesesuaian peran
  if (requiredRole && user.peran !== requiredRole) {
    return { success: false, code: 403, error: 'FORBIDDEN: Peran pengguna tidak memenuhi syarat.' };
  }
  
  // Verifikasi penugasan rombel guru
  if (kelasId) {
    const isAssigned = MockDatabase.assignments.some(function(asg) {
      return asg.pengguna_id === user.pengguna_id && asg.kelas_id === kelasId &&
        (!mapelId || asg.mapel_id === mapelId);
    });
    if (!isAssigned) {
      return { success: false, code: 403, error: 'FORBIDDEN: Anda tidak memiliki penugasan resmi pada rombel ini.' };
    }
  }
  
  return { success: true, authorized: true, role: user.peran };
}

function handleFailedLoginAttempt_(username) {
  const user = Object.values(MockDatabase.users).find(u => u.username === username);
  if (!user) return { locked: false, attempts: 0 };
  
  user.failed_attempts += 1;
  if (user.failed_attempts >= 5) {
    user.locked_until = Date.now() + 15 * 60 * 1000; // Lock 15 menit
    return { locked: true, attempts: user.failed_attempts, locked_until: user.locked_until };
  }
  return { locked: false, attempts: user.failed_attempts };
}

// ============================================================================
// 5. RUNNER PENGUJIAN BENCHMARK RESMI
// ============================================================================

function runPhase2Benchmark() {
  const results = {
    timestamp: new Date().toISOString(),
    environment: typeof process !== 'undefined' ? 'Node.js V8 (' + process.version + ')' : 'Google Apps Script V8 Native',
    passwordHashing: [],
    tokenEntropy: {},
    authorizationScenarios: [],
    constantTimeVerification: {},
    bruteForceThrottling: {},
    circuitBreakerEvaluation: {}
  };

  Logger.log('================================================================');
  Logger.log('PHASE 2: MEMULAI PENGUJIAN KEAMANAN & AUTENTIKASI TERISOLASI');
  Logger.log('Runtime: ' + results.environment);
  Logger.log('================================================================\n');

  // --------------------------------------------------------------------------
  // UJI 1: Tolok Ukur Waktu Eksekusi Hashing Password
  // --------------------------------------------------------------------------
  Logger.log('--- 1. UJI TOLOK UKUR DERIVASI PASSWORD ---');
  const testPassword = 'PasswordGuruSD#2026';
  const testSalt = generateSalt16Bytes_();
  const testPepper = 'SECRET_SERVER_PEPPER_KEY_ABC123';
  const iterationTiers = [100, 500, 1000, 2000, 4000];

  for (let i = 0; i < iterationTiers.length; i++) {
    const iter = iterationTiers[i];
    
    // Benchmark PBKDF2-HMAC-SHA256
    const t0 = Date.now();
    const hashPbkdf2 = pbkdf2HmacSha256_(testPassword, testSalt, iter, testPepper);
    const dtPbkdf2 = Date.now() - t0;
    
    // Verifikasi deterministik & ketepatan password salah
    const hashPbkdf2Verify = pbkdf2HmacSha256_(testPassword, testSalt, iter, testPepper);
    const hashPbkdf2Wrong = pbkdf2HmacSha256_('WrongPassword123', testSalt, iter, testPepper);
    const pbkdf2Valid = constantTimeEquals_(hashPbkdf2, hashPbkdf2Verify);
    const pbkdf2RejectsWrong = !constantTimeEquals_(hashPbkdf2, hashPbkdf2Wrong);

    // Benchmark Repeated HMAC-SHA256
    const t1 = Date.now();
    const hashRepHmac = repeatedHmacSha256_(testPassword, testSalt, iter, testPepper);
    const dtRepHmac = Date.now() - t1;

    const row = {
      iterations: iter,
      pbkdf2Ms: dtPbkdf2,
      repeatedHmacMs: dtRepHmac,
      pbkdf2SampleHash: hashPbkdf2.substring(0, 16) + '...',
      deterministicPass: pbkdf2Valid,
      wrongPasswordRejected: pbkdf2RejectsWrong,
      meetsLatencyTarget: dtPbkdf2 < 1000
    };
    results.passwordHashing.push(row);

    Logger.log('Iterasi: ' + iter + ' | PBKDF2: ' + dtPbkdf2 + ' ms | Repeated HMAC: ' + dtRepHmac + ' ms | <1000ms: ' + (dtPbkdf2 < 1000));
  }

  // --------------------------------------------------------------------------
  // UJI 2: Karakteristik Token Sesi & Entropi
  // --------------------------------------------------------------------------
  Logger.log('\n--- 2. UJI FORMAT DAN KEUNIKAN TOKEN SESI ---');
  const tokenSampleSize = 5000;
  const tokenSet = new Set();
  const tokenLengths = new Set();
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  let allMatchUuidV4 = true;

  for (let k = 0; k < tokenSampleSize; k++) {
    const tk = Utilities.getUuid();
    tokenSet.add(tk);
    tokenLengths.add(tk.length);
    if (!uuidRegex.test(tk)) {
      allMatchUuidV4 = false;
    }
  }

  results.tokenEntropy = {
    sampleSize: tokenSampleSize,
    uniqueCount: tokenSet.size,
    collisionsDetected: tokenSampleSize - tokenSet.size,
    strictly36Chars: tokenLengths.size === 1 && tokenLengths.has(36),
    formatUuidV4Valid: allMatchUuidV4,
    sha256HashLength: hashTokenSha256_(Utilities.getUuid()).length,
    nominalEntropyBits: 122 // RFC 4122 standard
  };

  Logger.log('Sampel Token: ' + tokenSampleSize + ' | Unik: ' + tokenSet.size + ' | Kolisi: ' + results.tokenEntropy.collisionsDetected);
  Logger.log('Format UUID v4 Valid: ' + allMatchUuidV4 + ' | Panjang Hash SHA-256: ' + results.tokenEntropy.sha256HashLength + ' chars');

  // --------------------------------------------------------------------------
  // UJI 3: Simulasi 6 Skenario Otorisasi Backend Server-Side Zero-Trust
  // --------------------------------------------------------------------------
  Logger.log('\n--- 3. UJI SKENARIO OTORISASI BACKEND ZERO-TRUST ---');
  
  // Skenario 1: Admin aktif memanggil endpoint kelas mana pun
  const adminSession = issueSession_('USR-ADM-01', 8);
  const sc1Auth = validateSessionMiddleware_(adminSession.rawToken);
  const sc1Guard = verifyAuthorizationGuard_(sc1Auth, 'admin', 'KLS-02', 'MPL-001');
  results.authorizationScenarios.push({
    id: 'SC-01',
    description: 'Admin aktif mengakses data rombel lintas jenjang (KLS-02)',
    expectedResult: 'ALLOWED (200 OK)',
    actualResult: sc1Guard.authorized ? 'ALLOWED' : 'REJECTED',
    pass: sc1Guard.authorized === true
  });

  // Skenario 2: Guru Kelas 1 mengakses rombel binaannya (KLS-01)
  const guru1Session = issueSession_('USR-GUR-01', 8);
  const sc2Auth = validateSessionMiddleware_(guru1Session.rawToken);
  const sc2Guard = verifyAuthorizationGuard_(sc2Auth, 'guru', 'KLS-01', 'MPL-001');
  results.authorizationScenarios.push({
    id: 'SC-02',
    description: 'Guru 1 mengakses rombel binaan resmi (KLS-01)',
    expectedResult: 'ALLOWED (200 OK)',
    actualResult: sc2Guard.authorized ? 'ALLOWED' : 'REJECTED',
    pass: sc2Guard.authorized === true
  });

  // Skenario 3: Guru Kelas 1 mencoba memanggil data rombel Kelas 2 (KLS-02) -> WAJIB 403
  const sc3Guard = verifyAuthorizationGuard_(sc2Auth, 'guru', 'KLS-02', 'MPL-001');
  results.authorizationScenarios.push({
    id: 'SC-03',
    description: 'Guru 1 mencoba mengakses rombel di luar penugasan (KLS-02)',
    expectedResult: 'REJECTED (403 Forbidden)',
    actualResult: sc3Guard.success ? 'ALLOWED' : 'REJECTED (403)',
    pass: sc3Guard.success === false && sc3Guard.code === 403
  });

  // Skenario 4: Token sesi kedaluwarsa -> WAJIB 401
  const expiredSession = issueSession_('USR-GUR-01', -1); // Dibuat 1 jam lampau
  const sc4Auth = validateSessionMiddleware_(expiredSession.rawToken);
  results.authorizationScenarios.push({
    id: 'SC-04',
    description: 'Akses menggunakan token sesi kedaluwarsa (expired_at < now)',
    expectedResult: 'REJECTED (401 Unauthorized)',
    actualResult: sc4Auth.success ? 'ALLOWED' : 'REJECTED (401)',
    pass: sc4Auth.success === false && sc4Auth.code === 401
  });

  // Skenario 5: Sesi telah dicabut / logout -> WAJIB 401
  const revokedSession = issueSession_('USR-GUR-01', 8);
  revokeSession_(revokedSession.rawToken);
  const sc5Auth = validateSessionMiddleware_(revokedSession.rawToken);
  results.authorizationScenarios.push({
    id: 'SC-05',
    description: 'Akses menggunakan token sesi yang telah dicabut (logout)',
    expectedResult: 'REJECTED (401 Unauthorized)',
    actualResult: sc5Auth.success ? 'ALLOWED' : 'REJECTED (401)',
    pass: sc5Auth.success === false && sc5Auth.code === 401
  });

  // Skenario 6: Panggilan fungsi langsung tanpa menyertakan token -> WAJIB 401
  const sc6Auth = validateSessionMiddleware_(null);
  results.authorizationScenarios.push({
    id: 'SC-06',
    description: 'Pemanggilan fungsi langsung tanpa token sesi',
    expectedResult: 'REJECTED (401 Unauthorized)',
    actualResult: sc6Auth.success ? 'ALLOWED' : 'REJECTED (401)',
    pass: sc6Auth.success === false && sc6Auth.code === 401
  });

  for (let s = 0; s < results.authorizationScenarios.length; s++) {
    const sc = results.authorizationScenarios[s];
    Logger.log('[' + (sc.pass ? 'PASS' : 'FAIL') + '] ' + sc.id + ': ' + sc.description);
  }

  // --------------------------------------------------------------------------
  // UJI 4: Pembandingan Waktu Konstan (Constant-Time Comparison)
  // --------------------------------------------------------------------------
  Logger.log('\n--- 4. UJI PEMBANDINGAN WAKTU KONSTAN ---');
  const hA = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const hB = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const hDiffEarly = 'x1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const hDiffLate = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9x';

  results.constantTimeVerification = {
    exactMatch: constantTimeEquals_(hA, hB) === true,
    detectDiffFirstChar: constantTimeEquals_(hA, hDiffEarly) === false,
    detectDiffLastChar: constantTimeEquals_(hA, hDiffLate) === false,
    diffLengthRejection: constantTimeEquals_(hA, hA.substring(0, 32)) === false
  };
  Logger.log('Constant-Time Match: ' + results.constantTimeVerification.exactMatch + ' | Rejection Test: ' + (results.constantTimeVerification.detectDiffFirstChar && results.constantTimeVerification.detectDiffLastChar));

  // --------------------------------------------------------------------------
  // UJI 5: Brute-Force Throttling & Account Locking
  // --------------------------------------------------------------------------
  Logger.log('\n--- 5. UJI BRUTE-FORCE THROTTLING ---');
  const bfUsername = 'guru1';
  let lockResult = null;
  for (let attempt = 1; attempt <= 6; attempt++) {
    lockResult = handleFailedLoginAttempt_(bfUsername);
  }
  results.bruteForceThrottling = {
    triggeredLockAfter5Attempts: lockResult.locked === true,
    totalRecordedAttempts: lockResult.attempts,
    lockDurationMinutes: (lockResult.locked_until - Date.now()) / (60 * 1000)
  };
  Logger.log('Penguncian Akun Berfungsi: ' + results.bruteForceThrottling.triggeredLockAfter5Attempts + ' (Percobaan tercatat: ' + results.bruteForceThrottling.totalRecordedAttempts + ')');

  // --------------------------------------------------------------------------
  // UJI 6: Evaluasi Circuit Breaker
  // --------------------------------------------------------------------------
  const optimalPbkdf2 = results.passwordHashing.find(r => r.iterations === 2000);
  const circuitBreakerTriggered = !optimalPbkdf2 || !optimalPbkdf2.meetsLatencyTarget;
  results.circuitBreakerEvaluation = {
    evaluatedAlgorithm: 'PBKDF2-HMAC-SHA256',
    recommendedIterations: optimalPbkdf2 ? optimalPbkdf2.iterations : null,
    latencyMs: optimalPbkdf2 ? optimalPbkdf2.pbkdf2Ms : null,
    targetThresholdMs: 1000,
    circuitBreakerTripped: circuitBreakerTriggered,
    decision: circuitBreakerTriggered ? 'TRIGGER_FALLBACK_GOOGLE_AUTH' : 'PROCEED_WITH_INTERNAL_PBKDF2'
  };
  Logger.log('\n--- 6. EVALUASI GERBANG KEPUTUSAN CIRCUIT BREAKER ---');
  Logger.log('Keputusan: ' + results.circuitBreakerEvaluation.decision + ' (Latensi: ' + results.circuitBreakerEvaluation.latencyMs + ' ms)');

  return results;
}

// Eksekusi otomatis jika dijalankan via Node.js CLI
if (typeof module !== 'undefined' && require.main === module) {
  const output = runPhase2Benchmark();
  console.log('\nJSON Output:\n' + JSON.stringify(output, null, 2));
}
