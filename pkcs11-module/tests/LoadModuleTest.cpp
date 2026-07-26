// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// dlopen the built module and confirm C_GetFunctionList yields a non-null,
// version-stamped function list, and that C_Initialize / C_GetInfo / C_Finalize
// work standalone (no agent / no card needed). Also asserts the export surface
// is exactly C_GetFunctionList — every other symbol (including the other C_*)
// must be hidden by the version script.

#include "pkcs11.h"

#include <dlfcn.h>
#include <gtest/gtest.h>

namespace {

void* openModule()
{
    void* h = dlopen(LIBRESCRS_PKCS11_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    return h;
}

} // namespace

TEST(LoadModule, GetFunctionListReturnsVersionedList)
{
    void* h = openModule();
    ASSERT_NE(h, nullptr) << dlerror();

    auto getList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(h, "C_GetFunctionList"));
    ASSERT_NE(getList, nullptr) << "C_GetFunctionList not exported";

    CK_FUNCTION_LIST_PTR list = nullptr;
    ASSERT_EQ(getList(&list), CKR_OK);
    ASSERT_NE(list, nullptr);
    EXPECT_EQ(list->version.major, 2);
    EXPECT_EQ(list->version.minor, 40);
    EXPECT_NE(list->C_Initialize, nullptr);
    EXPECT_NE(list->C_Finalize, nullptr);
    EXPECT_NE(list->C_GetInfo, nullptr);
    EXPECT_NE(list->C_GetFunctionList, nullptr);

    dlclose(h);
}

TEST(LoadModule, GetFunctionListRejectsNull)
{
    void* h = openModule();
    ASSERT_NE(h, nullptr) << dlerror();
    auto getList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(h, "C_GetFunctionList"));
    ASSERT_NE(getList, nullptr);
    EXPECT_EQ(getList(nullptr), CKR_ARGUMENTS_BAD);
    dlclose(h);
}

TEST(LoadModule, InitializeGetInfoFinalizeStandalone)
{
    void* h = openModule();
    ASSERT_NE(h, nullptr) << dlerror();
    auto getList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(h, "C_GetFunctionList"));
    ASSERT_NE(getList, nullptr);
    CK_FUNCTION_LIST_PTR list = nullptr;
    ASSERT_EQ(getList(&list), CKR_OK);

    EXPECT_EQ(list->C_Initialize(nullptr), CKR_OK);

    CK_INFO info{};
    EXPECT_EQ(list->C_GetInfo(&info), CKR_OK);
    EXPECT_EQ(info.cryptokiVersion.major, 2);
    EXPECT_EQ(info.cryptokiVersion.minor, 40);

    EXPECT_EQ(list->C_Finalize(nullptr), CKR_OK);
    dlclose(h);
}

TEST(LoadModule, OnlyCGetFunctionListExported)
{
    // RTLD_LOCAL keeps the module out of the global namespace, so we probe the
    // handle directly. The internal C_* must NOT be resolvable by name.
    void* h = openModule();
    ASSERT_NE(h, nullptr) << dlerror();

    EXPECT_NE(dlsym(h, "C_GetFunctionList"), nullptr);

    // These are real functions inside the .so but the version script hides them;
    // callers must go through the function list, never dlsym.
    EXPECT_EQ(dlsym(h, "C_Initialize"), nullptr) << "C_Initialize leaked from the version script";
    EXPECT_EQ(dlsym(h, "C_Sign"), nullptr) << "C_Sign leaked from the version script";
    EXPECT_EQ(dlsym(h, "C_GetSlotList"), nullptr) << "C_GetSlotList leaked from the version script";

    dlclose(h);
}
