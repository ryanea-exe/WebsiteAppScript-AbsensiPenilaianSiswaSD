/**
 * SISTEM ABSENSI DAN PENILAIAN SISWA SD
 * Modul: app/setup.gs (Phase 3A — Setup Master Sheets)
 * 
 * Deskripsi:
 * Menginisialisasi dan memvalidasi struktur 21 lembar kerja basis data Google Sheets
 * serta baris konfigurasi default secara aman, idempoten, dan non-destruktif.
 *
 * Batasan Desain & Keamanan:
 * 1. Tidak dieksekusi secara otomatis saat file dimuat (hanya berupa deklarasi fungsi).
 * 2. Target spreadsheet wajib ditentukan secara eksplisit (mencegah salah sasaran).
 * 3. Idempoten mutlak: dilarang memanggil .clear() atau .clearContents() pada data pengguna.
 * 4. Header yang tidak cocok memicu penghentian seketika (throw Error) tanpa menimpa data.
 * 5. Pengaturan default ditambahkan secara check-before-insert (tidak menimpa nilai yang ada).
 * 6. Tidak menanam password tetap, akun publik, atau secret (SERVER_PEPPER) di kode sumber.
 *
 * Referensi Spesifikasi:
 * - .docs/.database.md (Kamus Data 21 Sheet & Header Resmi)
 * - .docs/.architecture.md (Bab 1 & Bab 8 - Prinsip Non-Destruktif)
 * - .docs/.tasks.md (Phase 3)
 */

/* global SpreadsheetApp */

// ============================================================================
// 1. SKEMA RESMI 21 LEMBAR KERJA DAN HEADER KOLOM BAKU
// ============================================================================

var MASTER_SHEETS_SCHEMA_ = {
  'Pengaturan': [
    'key', 'value', 'updated_at'
  ],
  'Pengguna': [
    'pengguna_id', 'username', 'password_hash', 'salt', 'nama_lengkap',
    'nip', 'peran', 'status', 'created_at', 'updated_at'
  ],
  'Sesi': [
    'sesi_id', 'pengguna_id', 'token_hash', 'expired_at', 'created_at'
  ],
  'TahunAjaran': [
    'tahun_ajaran_id', 'nama_tahun_ajaran', 'tanggal_mulai', 'tanggal_selesai',
    'status', 'created_at', 'updated_at'
  ],
  'Semester': [
    'semester_id', 'tahun_ajaran_id', 'nama_semester', 'tanggal_mulai',
    'tanggal_selesai', 'status', 'created_at', 'updated_at'
  ],
  'KalenderSekolah': [
    'kalender_id', 'tanggal', 'tahun_ajaran_id', 'semester_id',
    'jenis_hari', 'keterangan', 'created_at'
  ],
  'Kelas': [
    'kelas_id', 'tingkat', 'nama_rombel', 'status', 'created_at', 'updated_at'
  ],
  'Siswa': [
    'siswa_id', 'nis', 'nisn', 'nama_lengkap', 'jenis_kelamin',
    'tanggal_lahir', 'kelas_id_aktif', 'status', 'created_at', 'updated_at'
  ],
  'RiwayatKelas': [
    'riwayat_kelas_id', 'siswa_id', 'kelas_id', 'tahun_ajaran_id',
    'tanggal_mulai', 'tanggal_selesai', 'status', 'created_at'
  ],
  'MataPelajaran': [
    'mapel_id', 'kode_mapel', 'nama_mapel', 'status', 'created_at', 'updated_at'
  ],
  'PenugasanGuru': [
    'penugasan_id', 'pengguna_id', 'kelas_id', 'mapel_id', 'peran_penugasan',
    'tahun_ajaran_id', 'status', 'created_at', 'updated_at'
  ],
  'KelasMataPelajaran': [
    'kelas_mapel_id', 'kelas_id', 'mapel_id', 'tahun_ajaran_id', 'status', 'created_at'
  ],
  'Absensi': [
    'absensi_id', 'tanggal', 'siswa_id', 'kelas_id', 'status_absensi',
    'catatan', 'created_at', 'updated_at'
  ],
  'KomponenPenilaian': [
    'komponen_id', 'semester_id', 'nama_komponen', 'bobot', 'is_wajib',
    'urutan', 'status', 'created_at', 'updated_at'
  ],
  'Nilai': [
    'nilai_id', 'komponen_id', 'siswa_id', 'mapel_id', 'nilai',
    'catatan', 'updated_at'
  ],
  'NilaiAkhir': [
    'nilai_akhir_id', 'semester_id', 'siswa_id', 'mapel_id', 'nilai_akhir',
    'status_kelengkapan', 'snapshot_bobot_json', 'status_nilai', 'versi_koreksi',
    'finalized_by', 'finalized_at', 'last_revised_by', 'last_revised_at'
  ],
  'RiwayatKoreksiNilai': [
    'koreksi_id', 'nilai_akhir_id', 'semester_id', 'siswa_id', 'mapel_id',
    'versi_koreksi', 'nilai_sebelumnya', 'nilai_baru', 'alasan_revisi',
    'revised_by', 'revised_at'
  ],
  'AspekNonAkademik': [
    'aspek_id', 'nama_aspek', 'kategori', 'deskripsi', 'status', 'created_at'
  ],
  'PenilaianNonAkademik': [
    'nonakademik_id', 'semester_id', 'siswa_id', 'aspek_id', 'predikat',
    'deskripsi', 'updated_at'
  ],
  'CatatanSemester': [
    'catatan_id', 'semester_id', 'siswa_id', 'catatan_guru', 'status_kenaikan',
    'updated_at'
  ],
  'AuditLog': [
    'audit_id', 'timestamp', 'pengguna_id', 'peran', 'aksi', 'entitas',
    'entitas_id', 'status', 'rincian'
  ]
};

var DEFAULT_PENGATURAN_KEYS_ = [
  'nama_sekolah',
  'npsn',
  'alamat_sekolah',
  'nama_kepala_sekolah',
  'nip_kepala_sekolah',
  'tahun_ajaran_aktif_id',
  'semester_aktif_id',
  'titimangsa_laporan',
  'tanggal_laporan'
];

// ============================================================================
// 2. HELPER RESOLUSI SPREADSHEET TARGET
// ============================================================================

/**
 * Menyelesaikan target Google Spreadsheet secara eksplisit.
 * Mencegah pemilihan otomatis spreadsheet yang ambigu atau salah sasaran.
 *
 * @param {GoogleAppsScript.Spreadsheet.Spreadsheet|string} spreadsheetOrId
 * @return {GoogleAppsScript.Spreadsheet.Spreadsheet}
 */
function resolveSpreadsheet_(spreadsheetOrId) {
  if (!spreadsheetOrId) {
    throw new Error(
      'TARGET_ERROR: Target spreadsheet wajib ditentukan secara eksplisit. ' +
      'Berikan ID spreadsheet (string) atau objek Spreadsheet yang sah.'
    );
  }

  if (typeof spreadsheetOrId === 'string') {
    var trimmedId = spreadsheetOrId.trim();
    if (trimmedId === '') {
      throw new Error('TARGET_ERROR: ID spreadsheet tidak boleh berupa string kosong.');
    }
    try {
      return SpreadsheetApp.openById(trimmedId);
    } catch (err) {
      throw new Error(
        'TARGET_ERROR: Gagal membuka spreadsheet dengan ID "' + trimmedId + '". ' +
        'Pastikan ID benar dan akun eksekutor memiliki izin edit. Rincian: ' + err.message
      );
    }
  }

  if (typeof spreadsheetOrId === 'object' && typeof spreadsheetOrId.getSheetByName === 'function') {
    return spreadsheetOrId;
  }

  throw new Error('TARGET_ERROR: Parameter spreadsheetOrId tidak valid.');
}

// ============================================================================
// 3. FUNGSI UTAMA SETUP MASTER SHEETS (IDEMPOTEN & NON-DESTRUKTIF)
// ============================================================================

/**
 * Menginisialisasi dan memvalidasi struktur 21 lembar kerja basis data.
 * Dirancang idempoten mutlak: aman dipanggil berulang kali tanpa merusak data.
 *
 * @param {GoogleAppsScript.Spreadsheet.Spreadsheet|string} spreadsheetOrId
 * @return {Object} Laporan ringkasan hasil inisialisasi
 */
function setupMasterSheets_(spreadsheetOrId) {
  var spreadsheet = resolveSpreadsheet_(spreadsheetOrId);
  var sheetNames = Object.keys(MASTER_SHEETS_SCHEMA_);

  var createdSheets = [];
  var existingValidSheets = [];

  for (var i = 0; i < sheetNames.length; i++) {
    var sheetName = sheetNames[i];
    var expectedHeaders = MASTER_SHEETS_SCHEMA_[sheetName];
    var sheet = spreadsheet.getSheetByName(sheetName);

    if (!sheet) {
      // 1. Sheet belum ada -> Buat sheet baru dan inisialisasi baris header
      sheet = spreadsheet.insertSheet(sheetName);
      var headerRange = sheet.getRange(1, 1, 1, expectedHeaders.length);
      headerRange.setValues([expectedHeaders]);
      headerRange.setFontWeight('bold');
      sheet.setFrozenRows(1);
      createdSheets.push(sheetName);
    } else {
      // 2. Sheet sudah ada -> Validasi integritas baris header tanpa menimpa data
      var lastRow = sheet.getLastRow();
      var lastCol = sheet.getLastColumn();

      if (lastRow === 0 || lastCol === 0) {
        // Sheet kosong (tanpa baris sama sekali) -> Tulis header
        var emptyHeaderRange = sheet.getRange(1, 1, 1, expectedHeaders.length);
        emptyHeaderRange.setValues([expectedHeaders]);
        emptyHeaderRange.setFontWeight('bold');
        sheet.setFrozenRows(1);
        createdSheets.push(sheetName + ' (header_initialized)');
      } else {
        // Sheet telah memiliki konten -> Periksa integritas baris 1
        var actualHeaderRow = sheet.getRange(1, 1, 1, expectedHeaders.length).getValues()[0];
        var isHeaderMatch = true;
        var mismatchedColumns = [];

        for (var c = 0; c < expectedHeaders.length; c++) {
          var expectedCol = expectedHeaders[c];
          var actualCol = actualHeaderRow[c];
          if (actualCol !== expectedCol) {
            isHeaderMatch = false;
            mismatchedColumns.push(
              'Kolom ' + (c + 1) + ' (Diharapkan: "' + expectedCol + '", Ditemukan: "' + actualCol + '")'
            );
          }
        }

        if (!isHeaderMatch) {
          // GAGAL AMAN: Hentikan seketika untuk mencegah data corrupt / salah kolom
          throw new Error(
            'INTEGRITY_ERROR: Header pada sheet "' + sheetName + '" tidak sesuai dengan skema resmi.\n' +
            'Penyimpangan: ' + mismatchedColumns.join(', ') + '.\n' +
            'Eksekusi dihentikan seketika untuk melindungi integritas data pengguna.'
          );
        }

        existingValidSheets.push(sheetName);
      }
    }
  }

  // 3. Inisialisasi baris kunci default pada sheet Pengaturan (Check-Before-Insert)
  var pengaturanSheet = spreadsheet.getSheetByName('Pengaturan');
  var initializedKeys = initializeDefaultPengaturan_(pengaturanSheet);

  return {
    success: true,
    spreadsheetId: spreadsheet.getId(),
    createdSheetsCount: createdSheets.length,
    createdSheets: createdSheets,
    validatedSheetsCount: existingValidSheets.length,
    validatedSheets: existingValidSheets,
    initializedKeysCount: initializedKeys.length,
    initializedKeys: initializedKeys,
    timestamp: new Date().toISOString()
  };
}

// ============================================================================
// 4. HELPER INISIALISASI PENGATURAN DEFAULT (CHECK-BEFORE-INSERT)
// ============================================================================

/**
 * Menambahkan kunci default pada sheet Pengaturan jika belum terdaftar.
 * Nilai yang sudah ada tidak akan pernah ditimpa atau diubah.
 *
 * @param {GoogleAppsScript.Spreadsheet.Sheet} sheet
 * @return {Array<string>} Daftar kunci baru yang berhasil ditambahkan
 */
function initializeDefaultPengaturan_(sheet) {
  var lastRow = sheet.getLastRow();
  var existingKeys = {};

  if (lastRow > 1) {
    var keyRangeValues = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
    for (var r = 0; r < keyRangeValues.length; r++) {
      var k = String(keyRangeValues[r][0]).trim();
      if (k !== '') {
        existingKeys[k] = true;
      }
    }
  }

  var nowIso = new Date().toISOString();
  var newRowsToInsert = [];
  var newKeysList = [];

  for (var i = 0; i < DEFAULT_PENGATURAN_KEYS_.length; i++) {
    var targetKey = DEFAULT_PENGATURAN_KEYS_[i];
    if (!existingKeys[targetKey]) {
      newRowsToInsert.push([targetKey, '', nowIso]);
      newKeysList.push(targetKey);
    }
  }

  if (newRowsToInsert.length > 0) {
    var targetStartRow = sheet.getLastRow() + 1;
    sheet.getRange(targetStartRow, 1, newRowsToInsert.length, 3).setValues(newRowsToInsert);
  }

  return newKeysList;
}

// ============================================================================
// 5. HELPER VALIDASI PASIF STRUKTUR DATABASE (READ-ONLY)
// ============================================================================

/**
 * Memvalidasi apakah 21 sheet dan seluruh header kolom pada spreadsheet target
 * telah memenuhi spesifikasi resmi tanpa melakukan modifikasi data apa pun.
 *
 * @param {GoogleAppsScript.Spreadsheet.Spreadsheet|string} spreadsheetOrId
 * @return {Object} Status kepatuhan struktur database
 */
function verifyDatabaseStructure_(spreadsheetOrId) {
  var spreadsheet = resolveSpreadsheet_(spreadsheetOrId);
  var sheetNames = Object.keys(MASTER_SHEETS_SCHEMA_);

  var missingSheets = [];
  var invalidHeaders = {};
  var validSheets = [];

  for (var i = 0; i < sheetNames.length; i++) {
    var sheetName = sheetNames[i];
    var expectedHeaders = MASTER_SHEETS_SCHEMA_[sheetName];
    var sheet = spreadsheet.getSheetByName(sheetName);

    if (!sheet) {
      missingSheets.push(sheetName);
    } else {
      var lastRow = sheet.getLastRow();
      if (lastRow === 0) {
        invalidHeaders[sheetName] = ['Sheet kosong tanpa baris header'];
      } else {
        var actualHeaderRow = sheet.getRange(1, 1, 1, expectedHeaders.length).getValues()[0];
        var diffs = [];
        for (var c = 0; c < expectedHeaders.length; c++) {
          if (actualHeaderRow[c] !== expectedHeaders[c]) {
            diffs.push(
              'Kolom ' + (c + 1) + ' (Diharapkan: "' + expectedHeaders[c] + '", Ditemukan: "' + actualHeaderRow[c] + '")'
            );
          }
        }
        if (diffs.length > 0) {
          invalidHeaders[sheetName] = diffs;
        } else {
          validSheets.push(sheetName);
        }
      }
    }
  }

  var isValid = (missingSheets.length === 0) && (Object.keys(invalidHeaders).length === 0);

  return {
    isValid: isValid,
    spreadsheetId: spreadsheet.getId(),
    totalExpectedSheets: sheetNames.length,
    validSheetsCount: validSheets.length,
    validSheets: validSheets,
    missingSheetsCount: missingSheets.length,
    missingSheets: missingSheets,
    invalidHeaders: invalidHeaders,
    checkedAt: new Date().toISOString()
  };
}
