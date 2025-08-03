
/* WARNING: Globals starting with '_' overlap smaller symbols at the same
 * address */

void BfsInsertPolicyEntry(dword *param_1, undefined8 param_2, longlong param_3,
                          undefined8 param_4, longlong token_user_info_class,
                          longlong token_origin_info_class,
                          longlong *policyEntryObject_frmArgs)

{
  longlong *plVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  code *pcVar4;
  bool bVar5;
  bool bVar6;
  uint NTStatusCode;
  longlong pagedPool_policyEntryObject;
  longlong DestinationSIDBuffer_TokenUser;
  longlong DestinationSIDBuffer_TokenOrigin;
  longlong lVar7;
  undefined8 uVar8;
  ulonglong DestinationSIDBufferLength;
  dword *pdVar9;
  undefined1 securityCookiePadding[32];
  undefined8 local_e0;
  char local_d8;
  longlong SourceSIDLocal_TokenUser;
  longlong SourceSIDLocal_TokenOrigin;
  undefined8 local_c0;
  longlong local_b8;
  dword *local_b0;
  undefined8 local_a8;
  dword local_a0[4];
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 *local_60;
  undefined8 local_58;
  ulonglong cookie_check;

  cookie_check = __security_cookie ^ (ulonglong)securityCookiePadding;
  DestinationSIDBuffer_TokenOrigin = 0;
  SourceSIDLocal_TokenUser = token_user_info_class;
  SourceSIDLocal_TokenOrigin = token_origin_info_class;
  bVar5 = false;
  local_90 = 0;
  uStack_88 = 0;
  local_a8 = 0;
  local_a0[0] = 0;
  local_a0[1] = 0;
  local_a0[2] = 0;
  local_a0[3] = 0;
  local_b8 = 0;
  local_d8 = '\0';
  bVar6 = false;
  local_e0 = param_2;
  local_c0 = param_4;
  local_b0 = param_1;
  KeEnterCriticalRegion();
  ExAcquirePushLockExclusiveEx(param_3, 0);
  DestinationSIDBufferLength = *(ulonglong *)(param_3 + 8);
  pagedPool_policyEntryObject = BfsLookupPolicyEntryHashTable(
      DestinationSIDBufferLength, local_c0, token_user_info_class,
      token_origin_info_class);
  if (pagedPool_policyEntryObject == 0) {
    DestinationSIDBuffer_TokenUser = ExAllocatePool2(
        0x100, (ulonglong) * (byte *)(SourceSIDLocal_TokenUser + 1) * 4 + 8,
        0x53736642);
    if ((DestinationSIDBuffer_TokenUser == 0) ||
        (DestinationSIDBuffer_TokenOrigin = ExAllocatePool2(
             0x100, (ulonglong) * (byte *)(token_origin_info_class + 1) * 4 + 8,
             0x53736642),
         DestinationSIDBuffer_TokenOrigin == 0))
      goto LAB_00006876;
    DestinationSIDBufferLength =
        (ulonglong)((uint) * (byte *)(SourceSIDLocal_TokenUser + 1) * 4 + 8);
    NTStatusCode =
        RtlCopySid(DestinationSIDBufferLength, DestinationSIDBuffer_TokenUser,
                   SourceSIDLocal_TokenUser);
    if ((int)NTStatusCode < 0) {
    LAB_0000690c:
      if (3 <.data) {
        local_e0 = CONCAT44(local_e0._4_4_, NTStatusCode);
      LAB_0000688e:
        local_60 = &local_e0;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(DestinationSIDBufferLength,
                                           &DAT_00013c91);
      }
    } else {
      DestinationSIDBufferLength =
          (ulonglong)((uint) * (byte *)(SourceSIDLocal_TokenOrigin + 1) * 4 +
                      8);
      NTStatusCode = RtlCopySid(DestinationSIDBufferLength,
                                DestinationSIDBuffer_TokenOrigin,
                                SourceSIDLocal_TokenOrigin);
      if ((int)NTStatusCode < 0) goto LAB_0000690c;
      pagedPool_policyEntryObject = ExAllocatePool2(0x100, 0x98, 0x45736642);
      if (pagedPool_policyEntryObject != 0) {
        LOCK();
        *(int *)(pagedPool_policyEntryObject + 0x90) =
            *(int *)(pagedPool_policyEntryObject + 0x90) + 1;
        UNLOCK();
        lVar7 = ExAllocatePool2(0x40, 0x18, 0x76736642);
        *(longlong *)(pagedPool_policyEntryObject + 0x28) = lVar7;
        if (lVar7 != 0) {
          *(longlong *)(pagedPool_policyEntryObject + 0x18) =
              DestinationSIDBuffer_TokenUser;
          *(longlong *)(pagedPool_policyEntryObject + 0x20) =
              DestinationSIDBuffer_TokenOrigin;
          *(undefined4 *)(pagedPool_policyEntryObject + 0x38) = 0x10000001;
          *(undefined4 *)(pagedPool_policyEntryObject + 0x68) = 0;
          *(undefined8 *)(pagedPool_policyEntryObject + 0x70) = 0;
          *(undefined8 *)(pagedPool_policyEntryObject + 0x78) = 0;
          *(undefined2 *)(pagedPool_policyEntryObject + 0x72) = 0;
          *(undefined8 *)(pagedPool_policyEntryObject + 0x78) = 0;
          *(undefined8 *)(pagedPool_policyEntryObject + 0x80) = 0;
          *(undefined8 *)(pagedPool_policyEntryObject + 0x88) = 0;
          *(undefined2 *)(pagedPool_policyEntryObject + 0x82) = 0;
          *(undefined8 *)(pagedPool_policyEntryObject + 0x88) = 0;
          KeInitializeEvent(lVar7, 0, 0);
          DestinationSIDBufferLength = *(ulonglong *)(param_3 + 8);
          NTStatusCode =
              BfsInsertEntryHashTable(DestinationSIDBufferLength, local_c0,
                                      pagedPool_policyEntryObject);
          if (-1 < (int)NTStatusCode) {
            LOCK();
            *(int *)(pagedPool_policyEntryObject + 0x90) =
                *(int *)(pagedPool_policyEntryObject + 0x90) + 1;
            UNLOCK();
            plVar1 = (longlong *)(param_3 + 0x10);
            local_d8 = '\x01';
            if ((longlong *)*plVar1 == plVar1) {
              ExSetTimer(*(undefined8 *)(param_3 + 0x20), 0xffffffffee1e5d00,
                         300000000);
            }
            puVar2 = *(undefined8 **)(param_3 + 0x18);
            plVar3 = (longlong *)(pagedPool_policyEntryObject + 0x40);
            if ((longlong *)*puVar2 != plVar1) goto LAB_00006d58;
            *plVar3 = (longlong)plVar1;
            *(undefined8 **)(pagedPool_policyEntryObject + 0x48) = puVar2;
            *puVar2 = plVar3;
            *(longlong **)(param_3 + 0x18) = plVar3;
            LOCK();
            *(undefined8 *)(pagedPool_policyEntryObject + 0x60) =
                _DAT_fffff78000000014;
            UNLOCK();
            goto LAB_00006a67;
          }
          goto LAB_0000690c;
        }
      }
    LAB_00006876:
      DestinationSIDBufferLength = 0xc0000017;
      NTStatusCode = 0xc0000017;
      if (3 <.data) {
        local_e0 = CONCAT44(local_e0._4_4_, 0xc0000017);
        NTStatusCode = 0xc0000017;
        goto LAB_0000688e;
      }
    }
  LAB_00006bb9:
    ExReleasePushLockExclusiveEx(param_3);
    KeLeaveCriticalRegion();
    bVar5 = false;
    bVar6 = false;
    if ((int)NTStatusCode < 0) {
    LAB_00006be6:
      if (pagedPool_policyEntryObject != 0) {
      LAB_00006beb:
        BfsDereferencePolicyEntryEx(pagedPool_policyEntryObject, '\0');
      }
      if (local_d8 != '\0') {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusiveEx(param_3, 0);
        pagedPool_policyEntryObject = BfsLookupPolicyEntryHashTable(
            *(undefined8 *)(param_3 + 8), local_c0, SourceSIDLocal_TokenUser,
            SourceSIDLocal_TokenOrigin);
        if (pagedPool_policyEntryObject == 0) {
          ExReleasePushLockExclusiveEx(param_3, 0);
          KeLeaveCriticalRegion();
        } else {
          plVar1 = (longlong *)(pagedPool_policyEntryObject + 0x40);
          *(undefined4 *)(pagedPool_policyEntryObject + 0x38) = 1;
          lVar7 = *plVar1;
          if ((*(longlong **)(lVar7 + 8) != plVar1) ||
              (plVar3 = *(longlong **)(pagedPool_policyEntryObject + 0x48),
               (longlong *)*plVar3 != plVar1)) {
          LAB_00006d58:
            pcVar4 = (code *)swi(0x29);
            (*pcVar4)(3);
            pcVar4 = (code *)swi(3);
            (*pcVar4)();
            return;
          }
          *plVar3 = lVar7;
          *(longlong **)(lVar7 + 8) = plVar3;
          DestinationSIDBufferLength =
              Feature_Servicing_BfsGAFeature__private_IsEnabledDeviceUsageNoInline();
          if ((int)DestinationSIDBufferLength != 0) {
            *plVar1 = 0;
            *(undefined8 *)(pagedPool_policyEntryObject + 0x48) = 0;
          }
          ExReleasePushLockExclusiveEx(param_3);
          KeLeaveCriticalRegion();
          KeSetEvent(*(undefined8 *)(pagedPool_policyEntryObject + 0x28), 0, 0);
          BfsDereferencePolicyEntryEx(pagedPool_policyEntryObject, '\0');
        }
      }
      if (bVar5) {
        RtlFreeUnicodeString(local_a0);
      }
      if (bVar6) {
        RtlFreeUnicodeString(&local_90);
      }
      if (DestinationSIDBuffer_TokenUser != 0) {
        ExFreePoolWithTag(DestinationSIDBuffer_TokenUser, 0);
      }
      if (DestinationSIDBuffer_TokenOrigin != 0) {
        ExFreePoolWithTag(DestinationSIDBuffer_TokenOrigin, 0);
      }
    }
    if (local_b8 != 0) {
      FltClose();
    }
  } else {
    DestinationSIDBuffer_TokenUser = DestinationSIDBuffer_TokenOrigin;
    if ((*(uint *)(pagedPool_policyEntryObject + 0x38) >> 0x1c & 1) == 0) {
      if (*(uint *)(pagedPool_policyEntryObject + 0x38) != 2) {
        NTStatusCode = 0xc0000001;
        goto LAB_0000690c;
      }
      *(undefined4 *)(pagedPool_policyEntryObject + 0x38) = 0x10000001;
      KeResetEvent(*(undefined8 *)(pagedPool_policyEntryObject + 0x28));
      LOCK();
      *(int *)(pagedPool_policyEntryObject + 0x90) =
          *(int *)(pagedPool_policyEntryObject + 0x90) + 1;
      UNLOCK();
    LAB_00006a67:
      ExReleasePushLockExclusiveEx(param_3, 0);
      KeLeaveCriticalRegion();
      pdVar9 = local_a0;
      NTStatusCode =
          RtlConvertSidToUnicodeString(pdVar9, SourceSIDLocal_TokenUser, 1);
      if (-1 < (int)NTStatusCode) {
        pdVar9 = (dword *)&local_90;
        bVar5 = true;
        NTStatusCode =
            RtlConvertSidToUnicodeString(pdVar9, SourceSIDLocal_TokenOrigin, 1);
        if (-1 < (int)NTStatusCode) {
          bVar6 = true;
          pdVar9 = local_b0;
          NTStatusCode = BfsOpenPolicyDirectory(local_b0, local_e0, local_a0,
                                                '\0', &local_b8);
          if ((-1 < (int)NTStatusCode) &&
              (pdVar9 = local_b0,
               NTStatusCode = BfsCreateStorage(local_b0, local_e0, local_b8,
                                               &local_90, &local_a8),
               -1 < (int)NTStatusCode)) {
            RtlFreeUnicodeString(local_a0);
            RtlFreeUnicodeString(&local_90);
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusiveEx(param_3);
            *(undefined8 *)(pagedPool_policyEntryObject + 0x30) = local_a8;
            *(undefined4 *)(pagedPool_policyEntryObject + 0x38) = 0x10000000;
            KeSetEvent(*(undefined8 *)(pagedPool_policyEntryObject + 0x28), 0,
                       0);
            *policyEntryObject_frmArgs = pagedPool_policyEntryObject;
            goto LAB_00006bb9;
          }
        }
      }
      if (3 <.data) {
        local_e0 = CONCAT44(local_e0._4_4_, NTStatusCode);
        local_60 = &local_e0;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(pdVar9, &DAT_00013c91);
      }
      goto LAB_00006be6;
    }
    LOCK();
    *(int *)(pagedPool_policyEntryObject + 0x90) =
        *(int *)(pagedPool_policyEntryObject + 0x90) + 1;
    UNLOCK();
    ExReleasePushLockExclusiveEx(param_3);
    KeLeaveCriticalRegion();
    if (*(int *)(pagedPool_policyEntryObject + 0x38) == 0x10000001) {
      uVar8 = *(undefined8 *)(pagedPool_policyEntryObject + 0x28);
      KeWaitForSingleObject(uVar8, 0, 0, 0);
      if (*(int *)(pagedPool_policyEntryObject + 0x38) != 0x10000000) {
        if (3 <.data) {
          local_e0 = CONCAT44(local_e0._4_4_, 0xc0000001);
          local_60 = &local_e0;
          local_58 = 4;
          _tlgWriteTransfer_EtwWriteTransfer(uVar8, &DAT_00013c91);
          DestinationSIDBuffer_TokenOrigin = 0;
          DestinationSIDBuffer_TokenUser = 0;
        }
        goto LAB_00006beb;
      }
    }
    *policyEntryObject_frmArgs = pagedPool_policyEntryObject;
  }
  __security_check_cookie(cookie_check ^ (ulonglong)securityCookiePadding);
  return;
}
