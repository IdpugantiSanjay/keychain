#include "catch_amalgamated.hpp"
#include "keychain/keychain.h"

using namespace keychain;

// clang-format off
CATCH_REGISTER_ENUM(keychain::ErrorType,
                    keychain::ErrorType::NoError,
                    keychain::ErrorType::GenericError,
                    keychain::ErrorType::NotFound,
                    keychain::ErrorType::Unavailable,
                    keychain::ErrorType::PasswordTooLong,
                    keychain::ErrorType::AccessDenied)
// clang-format on

void check_no_error(const Error &ec) {
    const std::string error =
        Catch::StringMaker<keychain::ErrorType>::convert(ec.type);
    INFO(error << " [" << ec.code << "] "
               << ": " << ec.message);
    CHECK(!ec);
}

TEST_CASE("Keychain", "[keychain]") {
    auto crud = [](const std::string &package,
                   const std::string &service,
                   const std::string &user,
                   const std::string &password_in) {
        Error ec{};
        getPassword(package, service, user, ec);
        REQUIRE(ec.type == ErrorType::NotFound);

        ec = Error{};
        setPassword(package, service, user, password_in, ec);
        check_no_error(ec);

        ec = Error{};
        auto password = getPassword(package, service, user, ec);
        check_no_error(ec);
        CHECK(password == password_in);

        const std::string better_password = "123456";

        ec = Error{};
        setPassword(package, service, user, better_password, ec);
        check_no_error(ec);

        ec = Error{};
        password = getPassword(package, service, user, ec);
        REQUIRE(!ec);
        CHECK(password == better_password);

        ec = Error{};
        deletePassword(package, service, user, ec);
        check_no_error(ec);
        ec = Error{};
        getPassword(package, service, user, ec);
        CHECK(ec.type == ErrorType::NotFound);
    };

    const std::string package = "com.example.keychain-tests";
    const std::string service = "test_service";
    const std::string user = "Admin";
    const std::string password = "hunter2";

    SECTION("the happily place") { crud(package, service, user, password); }

    SECTION("empty package name") { crud(package, "", user, password); }
    SECTION("empty service name") { crud(package, "", user, password); }
    SECTION("empty user name") { crud(package, service, "", password); }
    SECTION("empty password") { crud(package, service, user, ""); }
    SECTION("all empty") { crud("", "", "", ""); }

#ifdef KEYCHAIN_WINDOWS
    // Windows will report an error, other platforms succeed
    SECTION("long password (windows)") {
        const std::string longPassword(4097, '=');
        Error ec{};
        getPassword(package, service, user, ec);
        REQUIRE(ec.type == ErrorType::NotFound);

        ec = Error{};
        setPassword(package, service, user, longPassword, ec);
        CHECK(ec.type == ErrorType::PasswordTooLong);
    }
#else
    SECTION("long password (unix)") {
        const std::string longPassword(4097, '=');
        crud(package, service, user, longPassword);
    }
#endif

    SECTION("unicode") { crud("🙈.🙉.🙊", "💛", "👩💻", "🔑"); }

    SECTION("deleting a password that does not exist results in NotFound") {
        Error ec{};
        deletePassword("no.package", "no.service", "no.user", ec);
        CHECK(ec.type == ErrorType::NotFound);
    }

    SECTION("successful function call overrides previous Error to success") {
        Error ec{};
        ec.type = ErrorType::GenericError;
        setPassword(package, service, user, password, ec);
        check_no_error(ec);

        ec.type = ErrorType::GenericError;
        getPassword(package, service, user, ec);
        check_no_error(ec);

        ec.type = ErrorType::GenericError;
        deletePassword(package, service, user, ec);
        check_no_error(ec);
    }

#if defined(KEYCHAIN_MACOS) && defined(SIMULATE_FAILURES)
    SECTION("isAvailable fails at SecItemCopyMatching") {
        setenv("KEYCHAIN_TEST_SIMULATED_FAILURE", "1", 1);
        Error ec{};
        bool available = isAvailable(ec);
        CHECK_FALSE(available);
        CHECK(ec.type == ErrorType::Unavailable);
        CHECK(ec.message.find("Simulated failure: SecItemCopyMatching") !=
              std::string::npos);
        unsetenv("KEYCHAIN_TEST_SIMULATED_FAILURE");
    }
#endif

#if defined(KEYCHAIN_LINUX) && defined(SIMULATE_FAILURES)
    SECTION("isAvailable fails at SecretService creation") {
        setenv("KEYCHAIN_TEST_SIMULATED_FAILURE", "1", 1);
        Error ec{};
        bool available = isAvailable(ec);
        CHECK_FALSE(available);
        CHECK(ec.type == ErrorType::Unavailable);
        CHECK(ec.message.find("Simulated failure: SecretService unavailable") !=
              std::string::npos);
        unsetenv("KEYCHAIN_TEST_SIMULATED_FAILURE");
    }
#endif

    SECTION("isAvailable returns true and no error on supported platforms") {
        Error ec{};
        bool available = isAvailable(ec);

        REQUIRE(available);
        check_no_error(ec);
    }

    SECTION("listPasswords returns empty list for unknown package") {
        Error ec{};
        auto entries = listPasswords("com.example.no-such-package", ec);
        check_no_error(ec);
        CHECK(entries.empty());
    }

    SECTION("listPasswords returns entries after setPassword") {
        const std::string pkg = "com.example.keychain-list-tests";
        Error ec{};
        setPassword(pkg, service, user, password, ec);
        check_no_error(ec);

        ec = Error{};
        auto entries = listPasswords(pkg, ec);
        check_no_error(ec);
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].service == service);
        CHECK(entries[0].user == user);

        ec = Error{};
        deletePassword(pkg, service, user, ec);
        check_no_error(ec);
    }

    SECTION("listPasswords reflects multiple credentials") {
        const std::string pkg = "com.example.keychain-list-multi";
        Error ec{};
        setPassword(pkg, "svc1", "alice", password, ec);
        check_no_error(ec);
        ec = Error{};
        setPassword(pkg, "svc2", "bob", password, ec);
        check_no_error(ec);

        ec = Error{};
        auto entries = listPasswords(pkg, ec);
        check_no_error(ec);
        CHECK(entries.size() == 2);

        ec = Error{};
        deletePassword(pkg, "svc1", "alice", ec);
        check_no_error(ec);
        ec = Error{};
        deletePassword(pkg, "svc2", "bob", ec);
        check_no_error(ec);
    }

    SECTION("listPasswords returns empty after all passwords deleted") {
        const std::string pkg = "com.example.keychain-list-delete";
        Error ec{};
        setPassword(pkg, service, user, password, ec);
        check_no_error(ec);

        ec = Error{};
        deletePassword(pkg, service, user, ec);
        check_no_error(ec);

        ec = Error{};
        auto entries = listPasswords(pkg, ec);
        check_no_error(ec);
        CHECK(entries.empty());
    }

    SECTION("listPasswords excludes entries with empty service") {
        const std::string pkg = "com.example.keychain-list-blank-svc";
        Error ec{};
        setPassword(pkg, "", user, password, ec);
        // only proceed if the platform accepted the entry
        if (!ec) {
            ec = Error{};
            auto entries = listPasswords(pkg, ec);
            check_no_error(ec);
            for (const auto &e : entries)
                CHECK_FALSE(e.service.empty());

            ec = Error{};
            deletePassword(pkg, "", user, ec);
        }
    }

    SECTION("listPasswords excludes entries with empty user") {
        const std::string pkg = "com.example.keychain-list-blank-usr";
        Error ec{};
        setPassword(pkg, service, "", password, ec);
        if (!ec) {
            ec = Error{};
            auto entries = listPasswords(pkg, ec);
            check_no_error(ec);
            for (const auto &e : entries)
                CHECK_FALSE(e.user.empty());

            ec = Error{};
            deletePassword(pkg, service, "", ec);
        }
    }

    SECTION("listPasswords excludes entries with whitespace-only service") {
        const std::string pkg = "com.example.keychain-list-ws-svc";
        Error ec{};
        setPassword(pkg, "   ", user, password, ec);
        if (!ec) {
            ec = Error{};
            auto entries = listPasswords(pkg, ec);
            check_no_error(ec);
            for (const auto &e : entries)
                CHECK(e.service.find_first_not_of(" \t\r\n") !=
                      std::string::npos);

            ec = Error{};
            deletePassword(pkg, "   ", user, ec);
        }
    }

    SECTION("listPasswords excludes entries with whitespace-only user") {
        const std::string pkg = "com.example.keychain-list-ws-usr";
        Error ec{};
        setPassword(pkg, service, "   ", password, ec);
        if (!ec) {
            ec = Error{};
            auto entries = listPasswords(pkg, ec);
            check_no_error(ec);
            for (const auto &e : entries)
                CHECK(e.user.find_first_not_of(" \t\r\n") !=
                      std::string::npos);

            ec = Error{};
            deletePassword(pkg, service, "   ", ec);
        }
    }
}
