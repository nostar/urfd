/*
 *   Copyright (c) 2024 by Thomas A. Early N7TAE
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "DMRScanner.h"
#include <iostream>
#include <cassert>
#include <thread>
#include <vector>

// Simple test helper
#define ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << "FAILED: " << msg << " (" << #cond << ")" << std::endl; \
        return 1; \
    } else { \
        std::cout << "PASS: " << msg << std::endl; \
    }

int main()
{
    std::cout << "Running DMRScanner Tests..." << std::endl;

    // Test 1: Single Mode Logic
    {
        std::cout << "\n--- Test 1: Single Mode ---" << std::endl;
        CDMRScanner scanner;
        scanner.Configure(true, 600, 5); // Single mode, 10m timeout, 5s hold

        scanner.AddSubscription(4001, 1, 600);
        ASSERT(scanner.IsSubscribed(4001), "TG 4001 should be subscribed");

        scanner.AddSubscription(4002, 1, 600);
        ASSERT(scanner.IsSubscribed(4002), "TG 4002 should be subscribed");
        ASSERT(!scanner.IsSubscribed(4001), "TG 4001 should be removed in single mode");
    }

    // Test 2: Multi Mode Logic
    {
        std::cout << "\n--- Test 2: Multi Mode ---" << std::endl;
        CDMRScanner scanner;
        scanner.Configure(false, 600, 5); // Multi mode

        scanner.AddSubscription(4001, 1, 600);
        scanner.AddSubscription(4002, 1, 600);
        ASSERT(scanner.IsSubscribed(4001), "TG 4001 should remain");
        ASSERT(scanner.IsSubscribed(4002), "TG 4002 should remain");
    }

    // Test 3: Scanner Hold Logic
    {
        std::cout << "\n--- Test 3: Scanner Hold ---" << std::endl;
        CDMRScanner scanner;
        scanner.Configure(false, 600, 2); // 2s hold for testing

        scanner.AddSubscription(4001, 1, 600);
        scanner.AddSubscription(4002, 1, 600);

        // TG 4001 speaks
        ASSERT(scanner.CheckAccess(4001), "TG 4001 should be allowed");
        
        // Immediately TG 4002 tries
        ASSERT(!scanner.CheckAccess(4002), "TG 4002 should be blocked by hold");

        // Use same TG -> Should refresh hold
        ASSERT(scanner.CheckAccess(4001), "TG 4001 should still be allowed");

        // Wait exit hold
        std::cout << "Waiting for hold timer (2s)..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(2100)); // Sleep just over 2s due to precision
        
        // Now TG 4002 should work
        ASSERT(scanner.CheckAccess(4002), "TG 4002 should be allowed after hold");
        ASSERT(!scanner.CheckAccess(4001), "TG 4001 should now be blocked by new hold");
    }

    // Test 4: Options Parsing
    {
        std::cout << "\n--- Test 4: Options Parsing ---" << std::endl;
        CDMRScanner scanner;
        scanner.Configure(false, 600, 5);

        std::string opts = "TS1=101,102;TS2=201;AUTO=300";
        scanner.UpdateSubscriptions(opts);

        ASSERT(scanner.IsSubscribed(101), "Options TS1-101");
        ASSERT(scanner.IsSubscribed(102), "Options TS1-102");
        ASSERT(scanner.IsSubscribed(201), "Options TS2-201");
        
        // Check timeout (inspect via logic/expiry?) 
        // We can't easily inspect private member, but we can verify it expires.
        // Let's create a short timeout option test
        scanner.UpdateSubscriptions("TS1=999;AUTO=1");
        ASSERT(scanner.IsSubscribed(999), "TG 999 subscribed");
        std::this_thread::sleep_for(std::chrono::milliseconds(2100)); // Sleep > 2s for time_t resolution
        ASSERT(!scanner.IsSubscribed(999), "TG 999 should expire after 1s");
    }

    // Test 5: Unsubscribe (4000)
    {
        std::cout << "\n--- Test 5: Unsubscribe 4000 ---" << std::endl;
        CDMRScanner scanner;
        scanner.Configure(false, 600, 5);
        scanner.AddSubscription(4001, 1, 600);
        
        // Send 4000 on TS1
        scanner.AddSubscription(4000, 1, 0);
        ASSERT(!scanner.IsSubscribed(4001), "TG 4001 should be cleared by 4000");
    }

    std::cout << "\nAll Tests Passed!" << std::endl;
    return 0;
}
