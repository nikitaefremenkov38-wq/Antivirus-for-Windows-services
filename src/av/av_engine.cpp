#include "av_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <string_view>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace tray {
namespace {

constexpr wchar_t kAvSigningSecret[] = L"TrayAppAvRecordSigningKey";
constexpr ULONG kSha256Length = 32;
constexpr size_t kPrefixLength = 8;

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
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &dataLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    hashObject.resize(objectLength);
    if (BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    if (!bytes.empty() && BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) != 0) {
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

std::vector<uint8_t> BuildRecordSignature(const AvRecord& record) {
    std::vector<uint8_t> bytes;
    const auto prefixBytes = PrefixToBytes(record.objectSignaturePrefix);
    bytes.insert(bytes.end(), prefixBytes.begin(), prefixBytes.end());
    AppendUint32(&bytes, record.objectSignatureLength);
    bytes.insert(bytes.end(), record.objectSignature.begin(), record.objectSignature.end());
    AppendUint64(&bytes, record.offsetBegin);
    AppendUint64(&bytes, record.offsetEnd);
    AppendUint32(&bytes, static_cast<uint32_t>(record.objectType));
    const std::wstring_view secret(kAvSigningSecret);
    const auto* secretBytes = reinterpret_cast<const uint8_t*>(secret.data());
    bytes.insert(bytes.end(), secretBytes, secretBytes + secret.size() * sizeof(wchar_t));
    return Sha256(bytes);
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
    for (const auto& [byte, nextState] : nodes[0].next) {
        (void)byte;
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

}  // namespace

bool AvEngine::LoadDemoBases() {
    Clear();

    bool okay = true;
    okay = okay && AddRecord(std::vector<uint8_t>{'I','n','v','o','k','e','-','M','i','m','i','k','a','t','z'},
                             0, (std::numeric_limits<uint64_t>::max)(), AvObjectType::PowerShellScript, L"Demo.PS.Mimikatz");
    okay = okay && AddRecord(std::vector<uint8_t>{'T','R','A','Y','A','V','_','P','E','_','T','E','S','T'},
                             128, 4096, AvObjectType::PeFile, L"Demo.PE.TestMarker");
    if (!okay) {
        Clear();
        return false;
    }

    automaton_ = BuildAutomaton(recordsByPrefix_);
    releaseDateUnix_ = NowUnix();
    return true;
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
                if (record.objectSignatureLength < kPrefixLength || offset + record.objectSignatureLength > bytes.size()) {
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

    recordsByPrefix_[record.objectSignaturePrefix].push_back(record);
    ++recordCount_;
    return true;
}

bool AvEngine::VerifyRecordSignature(const AvRecord& record) const {
    return record.avRecordSignature == BuildRecordSignature(record);
}

}  // namespace tray
