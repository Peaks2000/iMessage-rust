// Local Anisette primitives from apple-auth. The Rust client owns HTTP,
// identity storage and the Apple Account password / SMS code.
#include <apple_auth/core.hpp>
#include <algorithm>
#include <cstring>
#include <memory>

namespace {
using namespace apple_auth;
constexpr const char* filename = "adi.pb";
constexpr std::size_t maximum_profile = 4096;

HardwareId hardware_id(const unsigned char* bytes) {
    HardwareId id{};
    std::copy_n(bytes, id.size(), id.begin());
    return id;
}

template <typename F>
int checked(F&& f) noexcept {
    try {
        return f() ? 0 : 1;
    } catch (...) {
        return 1;
    }
}
}

extern "C" {
int imessage_adi_begin(const unsigned char* challenge, std::size_t length,
                      const unsigned char* hardware, uint32_t time, void** output,
                      unsigned char* request, std::size_t* written) noexcept {
    return checked([&] {
        auto session = std::make_unique<ProvisioningSession>(
            ByteView(challenge, length), hardware_id(hardware), time, ProfilePlatform::mac);
        const auto bytes = session->request();
        if (bytes.empty() || bytes.size() > maximum_profile) {
            return false;
        }
        std::memcpy(request, bytes.data(), bytes.size());
        *written = bytes.size();
        *output = session.release();
        return true;
    });
}

int imessage_adi_finish(void* handle, const unsigned char* response, std::size_t length,
                       const unsigned char* trust, const unsigned char* hardware,
                       unsigned char* state, std::size_t* written) noexcept {
    return checked([&] {
        Block key{};
        std::copy_n(trust, key.size(), key.begin());
        auto* session = static_cast<ProvisioningSession*>(handle);
        const auto profile = session->finish(ByteView(response, length), key);
        auto bytes = profile.export_file(hardware_id(hardware), filename);
        if (bytes.empty() || bytes.size() > maximum_profile) {
            return false;
        }
        std::memcpy(state, bytes.data(), bytes.size());
        *written = bytes.size();
        std::fill(bytes.begin(), bytes.end(), 0);
        return true;
    });
}

void imessage_adi_free(void* handle) noexcept {
    delete static_cast<ProvisioningSession*>(handle);
}

int imessage_adi_headers(const unsigned char* state, std::size_t length,
                        const unsigned char* hardware, int64_t time,
                        unsigned char* mid, unsigned char* otp) noexcept {
    return checked([&] {
        const auto profile = Profile::import_file(ByteView(state, length), hardware_id(hardware), filename);
        const auto machine = profile.machine_id();
        const auto code = profile.otp(time_counter(time));
        std::copy(machine.begin(), machine.end(), mid);
        std::copy(code.begin(), code.end(), otp);
        return true;
    });
}
}
