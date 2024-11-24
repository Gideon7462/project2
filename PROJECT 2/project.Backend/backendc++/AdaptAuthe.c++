#include <iostream>
#include <string>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <memory>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <thread>
#include <curl/curl.h>

class User {
public:
    std::string username;
    std::string passwordHash;

    User(const std::string& uname, const std::string& pwd)
        : username(uname) {
        passwordHash = hashPassword(pwd);
    }

    static std::string hashPassword(const std::string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), hash);

        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return oss.str();
    }
};

class AdaptiveAuth {
private:
    sql::mysql::MySQL_Driver* driver;
    std::unique_ptr<sql::Connection> con;
    const std::string ipstackApiKey = "f4b322a8bbdfeb218cc0053a8705571f"; // actual API key for Ipstack
    std::string userPhone; // User's registered phone number for OTP
    std::string apiKey = "MzQ3ODcwNGQ0ZTQ5NDQzMDM3NzUzMTU5NWE2ZTc4NmY="; // control.txtlocal api key
    std::string senderPhone = "+254110157101"; // Your own phone number. creater phone number.

public:
    AdaptiveAuth(const std::string& phone = "") : userPhone(phone) {
        try {
            driver = sql::mysql::get_mysql_driver_instance();
            con.reset(driver->connect("tcp://127.0.0.1:3306", "root", "Temp@2019"));
            con->setSchema("tenant_database");
        } catch (sql::SQLException& e) {
            std::cerr << "Error connecting to database: " << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    ~AdaptiveAuth() {
        // Connection will be closed automatically when the object goes out of scope.
    }

    bool authenticateUser(const std::string& username, const std::string& password, const std::string& ipAddress, const std::string& deviceFingerprint) {
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement(
            "SELECT id, password_hash FROM users WHERE username = ?"
        ));
        pstmt->setString(1, username);

        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            std::string storedHash = res->getString("password_hash");
            std::string inputHash = User::hashPassword(password);

            if (storedHash == inputHash) {
                // Successful authentication, log the attempt and evaluate risk
                int userId = res->getInt("id");
                logAuthAttempt(userId, ipAddress, deviceFingerprint, "Success");

                // Evaluating the risk score and decide if MFA is required
                int riskScore = evaluateRiskFactors(userId, ipAddress, deviceFingerprint, std::chrono::system_clock::now());
                if (riskScore > 5) {
                    std::cout << "Warning: High risk detected. Please verify your identity." << std::endl;
                    return mfaVerification(userId, ipAddress); // Perform MFA if risk is high
                } else {
                    std::cout << "Authentication successful." << std::endl;
                    return true;
                }
            } else {
                std::cout << "Authentication failed. Invalid username or password." << std::endl;
                return false;
            }
        } else {
            std::cout << "Authentication failed. User not found." << std::endl;
            return false;
        }
    }

    void logAuthAttempt(int userId, const std::string& ipAddress, const std::string& deviceFingerprint, const std::string& status) {
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement(
            "INSERT INTO auth_logs(user_id, ip_address, device_fingerprint, login_time, status) VALUES (?, ?, ?, NOW(), ?)"
        ));
        pstmt->setInt(1, userId);
        pstmt->setString(2, ipAddress);
        pstmt->setString(3, deviceFingerprint);
        pstmt->setString(4, status);
        pstmt->executeUpdate();
    }

    int evaluateRiskFactors(int userId, const std::string& ipAddress, const std::string& deviceFingerprint, const std::chrono::system_clock::time_point& loginTime) {
        int riskScore = 0;

        // 1. Time of Login
        std::tm* currentTime = std::localtime(&std::chrono::system_clock::to_time_t(loginTime));
        int hour = currentTime->tm_hour;
        if (hour < 6 || hour > 22) {
            riskScore += 2; // Odd hours are risky
        }

        // 2. IP Address - Check recent IP addresses
        if (checkRecentLoginInfo(userId, "ip_address", ipAddress)) {
            riskScore += 3; // New IP address
        }

        // 3. Device Fingerprint - Check recent devices
        if (checkRecentLoginInfo(userId, "device_fingerprint", deviceFingerprint)) {
            riskScore += 2; // Unrecognized device
        }

        // 4. Failed Attempts in Last 10 Minutes
        if (checkFailedAttempts(userId)) {
            riskScore += 3; // Multiple failed attempts
        }

        // 5. Geolocation - Check geolocation of IP address
        if (isNewGeolocation(ipAddress, userId)) {
            riskScore += 3; // New geolocation
        }

        return riskScore;
    }

    bool checkRecentLoginInfo(int userId, const std::string& column, const std::string& value) {
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement(
            "SELECT 1 FROM auth_logs WHERE user_id = ? AND " + column + " = ? ORDER BY login_time DESC LIMIT 5"
        ));
        pstmt->setInt(1, userId);
        pstmt->setString(2, value);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        return res->next(); // If there's a match, it's a known device/IP
    }

    bool checkFailedAttempts(int userId) {
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement(
            "SELECT COUNT(*) AS failed_attempts FROM auth_logs WHERE user_id = ? AND status = 'Failure' AND login_time > NOW() - INTERVAL 10 MINUTE"
        ));
        pstmt->setInt(1, userId);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next() && res->getInt("failed_attempts") > 5) {
            return true;
        }
        return false;
    }

    bool isNewGeolocation(const std::string& ipAddress, int userId) {
        std::string country = getCountryFromIP(ipAddress);
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement(
            "SELECT country FROM user_geolocation WHERE user_id = ? ORDER BY last_seen DESC LIMIT 1"
        ));
        pstmt->setInt(1, userId);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next() && res->getString("country") != country) {
            return true; // Geolocation mismatch, considered risky
        }
        return false;
    }

    std::string getCountryFromIP(const std::string& ipAddress) {
        CURL *curl = curl_easy_init();
        std::string country;
        if(curl) {
            CURLcode res;
            std::string url = "http://api.ipstack.com/" + ipAddress + "?access_key= f4b322a8bbdfeb218cc0053a8705571f" + ipstackApiKey;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &country);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        return country;
    }

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
        size_t totalSize = size * nmemb;
        output->append((char*)contents, totalSize);
        return totalSize;
    }

bool mfaVerification(int userId, const std::string& ipAddress) {
    // Generate a secure 6-digit OTP
    std::random_device rd; // Random seed
    std::mt19937 gen(rd()); // Mersenne Twister RNG
    std::uniform_int_distribution<> dist(100000, 999999); // 6-digit range
    int otp = dist(gen);

    // Convert OTP to a string for consistency
    std::string otpString = std::to_string(otp);

    // Send OTP via SMS
    if (sendSMS(userPhone, otpString)) {
        std::cout << "An OTP has been sent to your registered phone number." << std::endl;

        // Timer for OTP validity
        auto startTime = std::chrono::system_clock::now();
        std::string userInput;

        while (true) {
            std::cout << "Enter OTP: ";
            std::cin >> userInput;

            // Validate numeric input
            if (!std::all_of(userInput.begin(), userInput.end(), ::isdigit)) {
                std::cout << "Invalid input. Please enter a numeric OTP." << std::endl;
                continue;
            }

            // Check if the OTP matches
            if (userInput == otpString) {
                std::cout << "OTP Verified Successfully." << std::endl;
                return true;
            }

            // Timeout check (e.g., 5 minutes)
            auto currentTime = std::chrono::system_clock::now();
            auto elapsedTime = std::chrono::duration_cast<std::chrono::minutes>(currentTime - startTime).count();
            if (elapsedTime > 5) {
                std::cout << "OTP expired. Please try again." << std::endl;
                return false;
            }

            std::cout << "Invalid OTP. Please try again." << std::endl;
        }
    } else {
        std::cout << "Failed to send OTP via SMS. Please contact support." << std::endl;
        return false;
    }
}

bool sendSMS(const std::string& phoneNumber, const std::string& otpMessage) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL." << std::endl;
        return false;
    }

    CURLcode res;
    std::string url = "https://control.txtlocal.co.uk/settings/apikeys/json";
    std::string postData = "MzQ3ODcwNGQ0ZTQ5NDQzMDM3NzUzMTU5NWE2ZTc4NmY=" + apiKey +
                           "&to=" + phoneNumber + "&from=" + senderPhone +
                           "&text=Your OTP is: " + otpMessage;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "CURL Error: " << curl_easy_strerror(res) << std::endl;
        return false;
    }

    return true;
}
}