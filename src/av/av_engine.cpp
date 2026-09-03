#include "av_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace tray {
namespace {

constexpr wchar_t kAvSigningSecret[] = L"TrayAppAvRecordSigningKey";
constexpr wchar_t kManifestSigningSecret[] = L"TrayAppManifestSigningKey";
constexpr ULONG kSha256Length = 32;
constexpr size_t kPrefixLength = 8;
constexpr uint32_t kFileFormatVersion = 1;
constexpr uint32_t kMagic = 0x42445641;  // AVDB

uint64_t NowUnix() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return (value.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

uint64_t PrefixFromBytes(const uint8_t* bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < kPrefixLength; ++i) {
        value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return value;
}

std::array<uint8_t, kPrefixLength> PrefixToBytes(uint64_t prefix) {
    std::array<uint8_t, kPrefixLength> bytes{};
    for (size_t i = 0; i < kPrefixLength; ++i) {
        bytes[i] = static_cast<uint8_t>((prefix >> (i * 8)) & 0xFF);
    }
    return bytes;
}

void AppendUint32(std::vector<uint8_t>* bytes, uint32_t value) {
    for (size_t i = 0; i < sizeof(value); ++i) {
        bytes->push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void AppendUint64(std::vector<uint8_t>* bytes, uint64_t value) {
    for (size_t i = 0; i < sizeof(value); ++i) {
        bytes->push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

bool ConsumeUint32(const std::vector<uint8_t>& bytes, size_t* offset, uint32_t* value) {
    if (*offset + sizeof(uint32_t) > bytes.size()) {
        return false;
    }
    uint32_t result = 0;
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        result |= static_cast<uint32_t>(bytes[*offset + i]) << (i * 8);
    }
    *offset += sizeof(uint32_t);
    *value = result;
    return true;
}

bool ConsumeUint64(const std::vector<uint8_t>& bytes, size_t* offset, uint64_t* value) {
    if (*offset + sizeof(uint64_t) > bytes.size()) {
        return false;
    }
    uint64_t result = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        result |= static_cast<uint64_t>(bytes[*offset + i]) << (i * 8);
    }
    *offset += sizeof(uint64_t);
    *value = result;
    return true;
}

bool ConsumeBytes(const std::vector<uint8_t>& bytes, size_t* offset, size_t count, std::vector<uint8_t>* out) {
    if (*offset + count > bytes.size()) {
        return false;
    }
    out->assign(bytes.begin() + static_cast<std::ptrdiff_t>(*offset),
                bytes.begin() + static_cast<std::ptrdiff_t>(*offset + count));
    *offset += count;
    return true;
}

std::wstring Utf8ToWide(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return L"";
    }
    const int charsNeeded = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                                 reinterpret_cast<const char*>(bytes.data()),
                                                 static_cast<int>(bytes.size()), nullptr, 0);
    if (charsNeeded <= 0) {
        return L"";
    }
    std::wstring value(static_cast<size_t>(charsNeeded), L'\0');
    const int converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                               reinterpret_cast<const char*>(bytes.data()),
                                               static_cast<int>(bytes.size()), value.data(),
                                               charsNeeded);
    if (converted != charsNeeded) {
        return L"";
    }
    return value;
}

std::vector<uint8_t> WideToUtf8Bytes(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int bytesNeeded = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                                 static_cast<int>(text.size()), nullptr, 0,
                                                 nullptr, nullptr);
    if (bytesNeeded <= 0) {
        return {};
    }
    std::vector<uint8_t> out(static_cast<size_t>(bytesNeeded));
    const int converted = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                               static_cast<int>(text.size()),
                                               reinterpret_cast<char*>(out.data()), bytesNeeded,
                                               nullptr, nullptr);
    if (converted != bytesNeeded) {
        return {};
    }
    return out;
}

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD dataLength = 0;
    std::vector<uint8_t> hashObject;
    std::vector<uint8_t> hashValue(kSha256Length);

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return {};
    }
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                          &dataLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    hashObject.resize(objectLength);
    if (BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    if (!bytes.empty() && BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()),
                                          static_cast<ULONG>(bytes.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    if (BCryptFinishHash(hash, hashValue.data(), static_cast<ULONG>(hashValue.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return hashValue;
}

std::vector<uint8_t> SignPayload(const std::vector<uint8_t>& payload, const wchar_t* secret) {
    std::vector<uint8_t> data = payload;
    const std::wstring_view secretView(secret);
    const auto* secretBytes = reinterpret_cast<const uint8_t*>(secretView.data());
    data.insert(data.end(), secretBytes, secretBytes + secretView.size() * sizeof(wchar_t));
    return Sha256(data);
}

std::vector<uint8_t> BuildRecordSignature(const AvRecord& record) {
    std::vector<uint8_t> bytes;
    const auto prefixBytes = PrefixToBytes(record.objectSignaturePrefix);
    bytes.insert(bytes.end(), prefixBytes.begin(), prefixBytes.end());
    AppendUint32(&bytes, record.objectSignatureLength);
    bytes.insert(bytes.end(), record.objectSignature.begin(), record.objectSignature.end());
    AppendUint64(&bytes, record.offsetBegin);
    AppendUint64(&bytes, record.offsetEnd);
    AppendUint32(&bytes, static_cast<uint32_t>(record.objectType));
    return SignPayload(bytes, kAvSigningSecret);
}

std::vector<AutomatonNode> BuildAutomaton(const std::map<uint64_t, std::vector<AvRecord>>& recordsByPrefix) {
    std::vector<AutomatonNode> nodes(1);

    for (const auto& [prefix, _] : recordsByPrefix) {
        const auto prefixBytes = PrefixToBytes(prefix);
        size_t state = 0;
        for (uint8_t byte : prefixBytes) {
            auto it = nodes[state].next.find(byte);
            if (it == nodes[state].next.end()) {
                nodes[state].next[byte] = nodes.size();
                nodes.push_back({});
                state = nodes.size() - 1;
            } else {
                state = it->second;
            }
        }
        nodes[state].outputs.push_back(prefix);
    }

    std::vector<size_t> queue;
    for (const auto& [_, nextState] : nodes[0].next) {
        nodes[nextState].fail = 0;
        queue.push_back(nextState);
    }

    for (size_t index = 0; index < queue.size(); ++index) {
        const size_t state = queue[index];
        for (const auto& [byte, nextState] : nodes[state].next) {
            queue.push_back(nextState);
            size_t fail = nodes[state].fail;
            while (fail != 0 && nodes[fail].next.find(byte) == nodes[fail].next.end()) {
                fail = nodes[fail].fail;
            }
            const auto failIt = nodes[fail].next.find(byte);
            nodes[nextState].fail = failIt != nodes[fail].next.end() ? failIt->second : 0;
            const auto& failOutputs = nodes[nodes[nextState].fail].outputs;
            nodes[nextState].outputs.insert(nodes[nextState].outputs.end(), failOutputs.begin(), failOutputs.end());
        }
    }

    return nodes;
}

bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>* bytes) {
    bytes->clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > static_cast<LONGLONG>(64 * 1024 * 1024)) {
        CloseHandle(file);
        return false;
    }

    bytes->resize(static_cast<size_t>(size.QuadPart));
    DWORD readBytes = 0;
    const BOOL readOk = bytes->empty() || ReadFile(file, bytes->data(), static_cast<DWORD>(bytes->size()), &readBytes, nullptr);
    CloseHandle(file);
    if (!readOk || readBytes != bytes->size()) {
        bytes->clear();
        return false;
    }
    return true;
}

bool WriteFileBytes(const std::wstring& path, const std::vector<uint8_t>& bytes) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    const BOOL writeOk = bytes.empty() || WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    CloseHandle(file);
    return writeOk && written == bytes.size();
}

std::vector<AvRecord> BuildBuiltinRecords() {
    std::vector<AvRecord> records;

    const std::vector<std::vector<uint8_t>> signatures = {
        {'I','n','v','o','k','e','-','M','i','m','i','k','a','t','z'},
        {'T','R','A','Y','A','V','_','P','E','_','T','E','S','T'}
    };
    const std::array<uint64_t, 2> offsetsBegin = {0, 128};
    const std::array<uint64_t, 2> offsetsEnd = {(std::numeric_limits<uint64_t>::max)(), 4096};
    const std::array<AvObjectType, 2> objectTypes = {AvObjectType::PowerShellScript, AvObjectType::PeFile};
    const std::array<std::wstring, 2> threatNames = {L"Demo.PS.Mimikatz", L"Demo.PE.TestMarker"};

    for (size_t i = 0; i < signatures.size(); ++i) {
        const auto& signature = signatures[i];
        AvRecord record;
        record.objectSignaturePrefix = PrefixFromBytes(signature.data());
        record.objectSignatureLength = static_cast<uint32_t>(signature.size());
        record.objectSignature = Sha256(signature);
        record.offsetBegin = offsetsBegin[i];
        record.offsetEnd = offsetsEnd[i];
        record.objectType = objectTypes[i];
        record.threatName = threatNames[i];
        record.avRecordSignature = BuildRecordSignature(record);
        records.push_back(std::move(record));
    }

    return records;
}

void SerializeRecord(const AvRecord& record, std::vector<uint8_t>* bytes) {
    AppendUint64(bytes, record.objectSignaturePrefix);
    AppendUint32(bytes, record.objectSignatureLength);
    AppendUint32(bytes, static_cast<uint32_t>(record.objectSignature.size()));
    bytes->insert(bytes->end(), record.objectSignature.begin(), record.objectSignature.end());
    AppendUint64(bytes, record.offsetBegin);
    AppendUint64(bytes, record.offsetEnd);
    AppendUint32(bytes, static_cast<uint32_t>(record.objectType));
    AppendUint32(bytes, static_cast<uint32_t>(record.avRecordSignature.size()));
    bytes->insert(bytes->end(), record.avRecordSignature.begin(), record.avRecordSignature.end());
    const std::vector<uint8_t> threatUtf8 = WideToUtf8Bytes(record.threatName);
    AppendUint32(bytes, static_cast<uint32_t>(threatUtf8.size()));
    bytes->insert(bytes->end(), threatUtf8.begin(), threatUtf8.end());
}

bool DeserializeRecord(const std::vector<uint8_t>& bytes, size_t* offset, AvRecord* record) {
    uint64_t prefix = 0;
    uint32_t signatureLength = 0;
    uint32_t objectSignatureBytes = 0;
    uint64_t offsetBegin = 0;
    uint64_t offsetEnd = 0;
    uint32_t objectType = 0;
    uint32_t avSignatureLength = 0;
    uint32_t threatLength = 0;

    if (!ConsumeUint64(bytes, offset, &prefix) ||
        !ConsumeUint32(bytes, offset, &signatureLength) ||
        !ConsumeUint32(bytes, offset, &objectSignatureBytes)) {
        return false;
    }

    std::vector<uint8_t> objectSignature;
    if (!ConsumeBytes(bytes, offset, objectSignatureBytes, &objectSignature) ||
        !ConsumeUint64(bytes, offset, &offsetBegin) ||
        !ConsumeUint64(bytes, offset, &offsetEnd) ||
        !ConsumeUint32(bytes, offset, &objectType) ||
        !ConsumeUint32(bytes, offset, &avSignatureLength)) {
        return false;
    }

    std::vector<uint8_t> avRecordSignature;
    if (!ConsumeBytes(bytes, offset, avSignatureLength, &avRecordSignature) ||
        !ConsumeUint32(bytes, offset, &threatLength)) {
        return false;
    }

    std::vector<uint8_t> threatUtf8;
    if (!ConsumeBytes(bytes, offset, threatLength, &threatUtf8)) {
        return false;
    }

    record->objectSignaturePrefix = prefix;
    record->objectSignatureLength = signatureLength;
    record->objectSignature = std::move(objectSignature);
    record->offsetBegin = offsetBegin;
    record->offsetEnd = offsetEnd;
    record->objectType = static_cast<AvObjectType>(objectType);
    record->avRecordSignature = std::move(avRecordSignature);
    record->threatName = Utf8ToWide(threatUtf8);
    return !record->threatName.empty() || threatUtf8.empty();
}

std::vector<uint8_t> BuildBasesPayload(uint64_t releaseDateUnix, const std::vector<AvRecord>& records) {
    std::vector<uint8_t> payload;
    AppendUint32(&payload, kMagic);
    AppendUint32(&payload, kFileFormatVersion);
    AppendUint64(&payload, releaseDateUnix);
    AppendUint32(&payload, static_cast<uint32_t>(records.size()));

    for (const AvRecord& record : records) {
        SerializeRecord(record, &payload);
    }
    return payload;
}

std::vector<uint8_t> BuildBasesFile(uint64_t releaseDateUnix, const std::vector<AvRecord>& records) {
    std::vector<uint8_t> payload = BuildBasesPayload(releaseDateUnix, records);
    const std::vector<uint8_t> manifestSignature = SignPayload(payload, kManifestSigningSecret);
    AppendUint32(&payload, static_cast<uint32_t>(manifestSignature.size()));
    payload.insert(payload.end(), manifestSignature.begin(), manifestSignature.end());
    return payload;
}

bool EnsureParentDirectory(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return true;
    }

    std::wstring current;
    current.reserve(path.size());
    for (size_t i = 0; i <= slash; ++i) {
        current.push_back(path[i]);
        if (path[i] != L'\\' && path[i] != L'/') {
            continue;
        }
        if (current.size() <= 3) {
            continue;
        }
        CreateDirectoryW(current.c_str(), nullptr);
    }
    return true;
}

}  // namespace

bool AvEngine::LoadDemoBases() {
    Clear();

    const std::vector<AvRecord> records = BuildBuiltinRecords();
    for (const AvRecord& record : records) {
        AddRecord(record);
    }

    automaton_ = BuildAutomaton(recordsByPrefix_);
    releaseDateUnix_ = NowUnix();
    return !recordsByPrefix_.empty();
}

bool AvEngine::SaveDefaultBasesToFile(const std::wstring& path) const {
    const std::vector<AvRecord> records = BuildBuiltinRecords();
    if (records.empty()) {
        return false;
    }

    EnsureParentDirectory(path);
    const std::vector<uint8_t> fileBytes = BuildBasesFile(NowUnix(), records);
    return WriteFileBytes(path, fileBytes);
}

AvLoadResult AvEngine::LoadBasesFromFile(const std::wstring& path, AvLoadStats* stats) {
    if (stats != nullptr) {
        *stats = {};
    }

    std::vector<uint8_t> bytes;
    const bool readOk = ReadFileBytes(path, &bytes);
    if (!readOk) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return AvLoadResult::FileMissing;
        }
        return AvLoadResult::IoError;
    }
    if (bytes.size() < sizeof(uint32_t) * 3 + sizeof(uint64_t)) {
        return AvLoadResult::FormatError;
    }

    size_t offset = 0;
    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t releaseDate = 0;
    uint32_t recordCount = 0;

    if (!ConsumeUint32(bytes, &offset, &magic) ||
        !ConsumeUint32(bytes, &offset, &version) ||
        !ConsumeUint64(bytes, &offset, &releaseDate) ||
        !ConsumeUint32(bytes, &offset, &recordCount)) {
        return AvLoadResult::FormatError;
    }

    if (magic != kMagic || version != kFileFormatVersion) {
        return AvLoadResult::FormatError;
    }

    std::vector<AvRecord> parsedRecords;
    parsedRecords.reserve(recordCount);
    for (uint32_t i = 0; i < recordCount; ++i) {
        AvRecord record;
        if (!DeserializeRecord(bytes, &offset, &record)) {
            return AvLoadResult::FormatError;
        }
        parsedRecords.push_back(std::move(record));
    }

    const size_t payloadEnd = offset;
    uint32_t manifestSignatureLength = 0;
    if (!ConsumeUint32(bytes, &offset, &manifestSignatureLength)) {
        return AvLoadResult::FormatError;
    }
    std::vector<uint8_t> manifestSignature;
    if (!ConsumeBytes(bytes, &offset, manifestSignatureLength, &manifestSignature)) {
        return AvLoadResult::FormatError;
    }
    if (offset != bytes.size()) {
        return AvLoadResult::FormatError;
    }

    const std::vector<uint8_t> payload(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(payloadEnd));
    const std::vector<uint8_t> expectedManifest = SignPayload(payload, kManifestSigningSecret);
    if (manifestSignature != expectedManifest) {
        return AvLoadResult::ManifestInvalid;
    }

    if (stats != nullptr) {
        stats->manifestValid = true;
        stats->totalRecords = recordCount;
    }

    Clear();
    for (const AvRecord& record : parsedRecords) {
        if (record.objectSignatureLength < kPrefixLength || record.objectSignature.empty()) {
            continue;
        }
        if (!VerifyRecordSignature(record)) {
            continue;
        }
        AddRecord(record);
    }

    if (stats != nullptr) {
        stats->loadedRecords = recordCount_;
        stats->rejectedRecords = recordCount_ <= recordCount ? recordCount - recordCount_ : 0;
    }

    if (recordCount_ == 0) {
        Clear();
        return AvLoadResult::NoValidRecords;
    }

    releaseDateUnix_ = releaseDate;
    automaton_ = BuildAutomaton(recordsByPrefix_);
    return AvLoadResult::Success;
}

void AvEngine::Clear() {
    recordsByPrefix_.clear();
    automaton_.clear();
    releaseDateUnix_ = 0;
    recordCount_ = 0;
}

bool AvEngine::HasBases() const {
    return !recordsByPrefix_.empty();
}

AvBasesInfo AvEngine::GetBasesInfo() const {
    return {HasBases(), releaseDateUnix_, recordCount_};
}

ScanMatchInfo AvEngine::ScanBytes(const std::vector<uint8_t>& bytes, AvObjectType objectType) const {
    if (bytes.size() < kPrefixLength || automaton_.empty()) {
        return {};
    }

    size_t state = 0;
    for (size_t index = 0; index < bytes.size(); ++index) {
        const uint8_t byte = bytes[index];
        while (state != 0 && automaton_[state].next.find(byte) == automaton_[state].next.end()) {
            state = automaton_[state].fail;
        }
        const auto nextIt = automaton_[state].next.find(byte);
        state = nextIt != automaton_[state].next.end() ? nextIt->second : 0;
        if (automaton_[state].outputs.empty() || index + 1 < kPrefixLength) {
            continue;
        }

        const uint64_t offset = static_cast<uint64_t>(index + 1 - kPrefixLength);
        for (uint64_t prefix : automaton_[state].outputs) {
            const auto recordsIt = recordsByPrefix_.find(prefix);
            if (recordsIt == recordsByPrefix_.end()) {
                continue;
            }
            for (const AvRecord& record : recordsIt->second) {
                if (!VerifyRecordSignature(record)) {
                    continue;
                }
                if (record.objectType != objectType) {
                    continue;
                }
                if (offset < record.offsetBegin || offset > record.offsetEnd) {
                    continue;
                }
                if (record.objectSignatureLength < kPrefixLength ||
                    offset + record.objectSignatureLength > bytes.size()) {
                    continue;
                }

                std::vector<uint8_t> candidate(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                               bytes.begin() + static_cast<std::ptrdiff_t>(offset + record.objectSignatureLength));
                const auto candidateHash = Sha256(candidate);
                if (candidateHash == record.objectSignature) {
                    return {true, record.objectType, offset, record.threatName};
                }
            }
        }
    }

    return {};
}

AvObjectType AvEngine::DetectObjectType(const std::wstring& path, const std::vector<uint8_t>& bytes) {
    const size_t dot = path.find_last_of(L'.');
    const std::wstring extension = dot == std::wstring::npos ? L"" : path.substr(dot);
    if (_wcsicmp(extension.c_str(), L".exe") == 0 || _wcsicmp(extension.c_str(), L".dll") == 0) {
        return AvObjectType::PeFile;
    }
    if (_wcsicmp(extension.c_str(), L".ps1") == 0) {
        return AvObjectType::PowerShellScript;
    }
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        return AvObjectType::PeFile;
    }
    return AvObjectType::Unknown;
}

std::wstring AvEngine::ObjectTypeToText(AvObjectType objectType) {
    switch (objectType) {
        case AvObjectType::PeFile:
            return L"PE";
        case AvObjectType::PowerShellScript:
            return L"PowerShell";
        default:
            return L"Unknown";
    }
}

void AvEngine::AddRecord(const AvRecord& record) {
    recordsByPrefix_[record.objectSignaturePrefix].push_back(record);
    ++recordCount_;
}

bool AvEngine::AddRecord(const std::vector<uint8_t>& signatureBytes,
                         uint64_t offsetBegin,
                         uint64_t offsetEnd,
                         AvObjectType objectType,
                         const std::wstring& threatName) {
    if (signatureBytes.size() < kPrefixLength) {
        return false;
    }

    AvRecord record;
    record.objectSignaturePrefix = PrefixFromBytes(signatureBytes.data());
    record.objectSignatureLength = static_cast<uint32_t>(signatureBytes.size());
    record.objectSignature = Sha256(signatureBytes);
    record.offsetBegin = offsetBegin;
    record.offsetEnd = offsetEnd;
    record.objectType = objectType;
    record.threatName = threatName;
    record.avRecordSignature = BuildRecordSignature(record);

    AddRecord(record);
    return true;
}

bool AvEngine::VerifyRecordSignature(const AvRecord& record) const {
    return record.avRecordSignature == BuildRecordSignature(record);
}

}  // namespace tray
