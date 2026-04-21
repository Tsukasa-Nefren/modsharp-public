/*
 * ModSharp
 * Copyright (C) 2023-2026 Kxnrl. All Rights Reserved.
 *
 * This file is part of ModSharp.
 * ModSharp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * ModSharp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with ModSharp. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CSTRIKE_INTERFACE_SCHEMA_H
#define CSTRIKE_INTERFACE_SCHEMA_H

#include <cstdint>

enum class FieldType_t : uint8_t;
struct DataMap_t;
class CSchemaSystemTypeScope;
struct SchemaClassInfoData_t;

struct CSchemaNetworkValue
{
    union {
        const char* m_sz_value;
        int         m_n_value;
        float       m_f_value;
        uintptr_t   m_p_value;
    };
};

struct SchemaMetadataEntryData_t
{
    const char*          m_name;
    CSchemaNetworkValue* m_value;
};

// taken from https://github.com/alliedmodders/hl2sdk/blob/cs2/public/schemasystem/schematypes.h
enum SchemaTypeCategory_t : uint8_t
{
    SCHEMA_TYPE_BUILTIN = 0,
    SCHEMA_TYPE_POINTER,
    SCHEMA_TYPE_BITFIELD,
    SCHEMA_TYPE_FIXED_ARRAY,
    SCHEMA_TYPE_ATOMIC,
    SCHEMA_TYPE_DECLARED_CLASS,
    SCHEMA_TYPE_DECLARED_ENUM,
    SCHEMA_TYPE_INVALID,
};

struct SchemaType_t
{
private:
    void* vtable;

public:
    const char*             m_pszTypeName;
    CSchemaSystemTypeScope* m_pTypeScope;
    SchemaTypeCategory_t    m_eTypeCategory;

    SchemaType_t() = delete;
};

struct SchemaClassFieldData_t
{
    const char*                m_pszName;
    SchemaType_t*              m_pType;
    int32_t                    m_nSingleInheritanceOffset;
    int32_t                    m_nMetadataCount;
    SchemaMetadataEntryData_t* m_pMetadata;
};

struct SchemaBaseClassInfoData_t
{
    uint32_t               m_nOffset;
    SchemaClassInfoData_t* m_pClass;
};

class CBaseEntity;
using InputFunc_t = void (CBaseEntity::*)(void* data);

struct TypeDescription_t
{
    FieldType_t    fieldType;
    const char*    fieldName;
    int32_t        fieldOffset; // Local offset value
    unsigned short fieldSize;
    int32_t        flags;
    // the name of the variable in the map/fgd data, or the name of the action
    const char* externalName;
    // pointer to the function set for save/restoring of custom data types
    void* pSaveRestoreOps;
    // for associating function with string names
    InputFunc_t inputFunc;

    // For embedding additional datatables inside this one
    union {
        DataMap_t*  td;
        const char* enumName;
    };

    // Stores the actual member variable size in bytes
    int32_t fieldSizeInBytes;
    // Tolerance for field errors for float fields
    float fieldTolerance;
    // For raw fields (including children of embedded stuff) this is the flattened offset
    int32_t    flatOffset[2];
    uint16_t   flatGroup;
    void*      pPredictionCopyOps;
    DataMap_t* m_pPredictionCopyDataMap;
};

struct DataMap_t
{
    TypeDescription_t* dataDesc;
    int32_t            dataNumFields;
    const char*        dataClassName;
    DataMap_t*         baseMap;
    void*              m_pOptimizedDataMap;
    int32_t            m_nPackedSize;
};

struct SchemaClassInfoData_t
{
    const char* GetName() const
    {
        return m_pszName;
    }

    int16_t GetFieldsSize() const
    {
        return m_nNumFields;
    }

    SchemaClassFieldData_t* GetFields() const
    {
        return m_pFields;
    }

    SchemaClassInfoData_t* GetParent() const
    {
        if (!m_BaseClasses)
            return nullptr;

        return m_BaseClasses->m_pClass;
    }

    int8_t GetBaseClassSize() const
    {
        return m_nNumBaseClasses;
    }

    SchemaBaseClassInfoData_t* GetBaseClasses() const
    {
        return m_BaseClasses;
    }

    int16_t GetMetadataSize() const
    {
        return m_nStaticMetadataCount;
    }

    SchemaMetadataEntryData_t* GetStaticMetadata() const
    {
        return m_pStaticMetadata;
    }

    DataMap_t* GetDataMap() const
    {
        return m_pDataMap;
    }

    SchemaClassInfoData_t() = delete;

private:
    // Layout as of CS2 update 2026-04-21.
    // Valve inserted a new 8-byte field at +0x18, pushing every subsequent member down by 8 bytes.
    // Struct size grew from 0x68 to 0x70.
    SchemaClassInfoData_t*     m_pClassInfo;                // 0x00
    const char*                m_pszName;                   // 0x08
    const char*                m_pszModule;                 // 0x10
    void*                      m_pUnknown_0x18;             // 0x18 (new, observed zero at init across all 1060 classes)
    int32_t                    m_nSize;                     // 0x20
    int16_t                    m_nNumFields;                // 0x24
    int16_t                    m_nStaticMetadataCount;      // 0x26
    int8_t                     m_nAlignOf;                  // 0x28
    int8_t                     m_nNumBaseClasses;           // 0x29
    int16_t                    m_nMultipleInheritanceDepth; // 0x2A
    int16_t                    m_nSingleInheritanceDepth;   // 0x2C
    int16_t                    m_nPadding_0x2E;             // 0x2E
    SchemaClassFieldData_t*    m_pFields;                   // 0x30
    SchemaBaseClassInfoData_t* m_BaseClasses;               // 0x38
    DataMap_t*                 m_pDataMap;                  // 0x40
    SchemaMetadataEntryData_t* m_pStaticMetadata;           // 0x48
    // +0x50  m_pTypeScope (runtime-populated)
    // +0x58  m_pDeclaredClass (runtime-populated)
    // +0x60  m_nFlags1 (uint32)
    // +0x64  m_nFlags2 (uint32)
    // +0x68  m_pfnManipulator
    // sizeof = 0x70
};

class CSchemaSystemTypeScope
{
public:
    SchemaClassInfoData_t* FindDeclaredClass(const char* pClass);
};

class ISchemaSystem
{
public:
    CSchemaSystemTypeScope* GetGlobalTypeScope();
    CSchemaSystemTypeScope* FindTypeScopeForModule(const char* module);
};

#endif
