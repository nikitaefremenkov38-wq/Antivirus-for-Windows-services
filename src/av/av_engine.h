#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace tray {

struct AutomatonNode {
    std::map<uint8_t, size_t> next;
    size_t fail{};
    std::vector<uint64_t> outputs;
};

enum class AvObjectType : uint32_t {
    Unknown = 0,
    PeFile = 1,
    PowerShellScript = 2,
};

struct AvRecord {
    uint64_t objectSignaturePrefix{};
    uint32_t objectSignatureLength{};
    std::vector<uint8_t> objectSignature;
    uint64_t offsetBegin{};
    uint64_t offsetEnd{};
    AvObjectType objectType{AvObjectType::Unknown};
    std::vector<uint8_t> avRecordSignature;
    std::wstring threatName;
};

struct AvBasesInfo {
    bool loaded{false};
    uint64_t releaseDateUnix{};
    uint32_t recordCount{};
};

struct ScanMatchInfo {
    bool malicious{false};
    AvObjectType objectType{AvObjectType::Unknown};
    uint64_t offset{};
    std::wstring threatName;
};

struct ScanSummary {
    uint32_t scannedObjects{};
    uint32_t maliciousObjects{};
    uint32_t failedObjects{};
    std::wstring details;
};

class AvEngine {
public:
    bool LoadDemoBases();
    void Clear();

    bool HasBases() const;
    AvBasesInfo GetBasesInfo() const;

    ScanMatchInfo ScanBytes(const std::vector<uint8_t>& bytes, AvObjectType objectType) const;

    static AvObjectType DetectObjectType(const std::wstring& path, const std::vector<uint8_t>& bytes);
    static std::wstring ObjectTypeToText(AvObjectType objectType);

private:
    bool AddRecord(const std::vector<uint8_t>& signatureBytes,
                   uint64_t offsetBegin,
                   uint64_t offsetEnd,
                   AvObjectType objectType,
                   const std::wstring& threatName);
    bool VerifyRecordSignature(const AvRecord& record) const;

    std::map<uint64_t, std::vector<AvRecord>> recordsByPrefix_;
    std::vector<AutomatonNode> automaton_;
    uint64_t releaseDateUnix_{};
    uint32_t recordCount_{};
};

}  // namespace tray
