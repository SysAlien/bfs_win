
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void BfsGetPolicyEntry(dword *param_1,undefined8 param_2,longlong param_3,byte *param_4,
                      byte *param_5,longlong *param_6)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  longlong lVar4;
  undefined1 auStackY_d8 [32];
  longlong local_98;
  longlong local_90;
  undefined8 local_88;
  longlong *local_60;
  undefined4 local_58;
  undefined4 local_54;
  ulonglong local_50;
  
  local_50 = __security_cookie ^ (ulonglong)auStackY_d8;
  local_98 = 0;
  local_88 = param_2;
  uVar1 = RtlLengthSid(param_4);
  BfsUpdateHash(param_4,uVar1,&local_98);
  uVar1 = RtlLengthSid(param_5);
  BfsUpdateHash(param_5,uVar1,&local_98);
  uVar3 = BfsFinalHash(&local_98);
  *param_6 = 0;
  KeEnterCriticalRegion();
  ExAcquirePushLockSharedEx(param_3,0);
  lVar4 = BfsLookupPolicyEntryHashTable(*(undefined8 *)(param_3 + 8),uVar3,param_4,param_5);
  local_90 = lVar4;
  if ((lVar4 == 0) || ((*(uint *)(lVar4 + 0x38) & 0x10000000) == 0)) {
    ExReleasePushLockSharedEx(param_3,0);
    KeLeaveCriticalRegion();
    iVar2 = BfsInsertPolicyEntry
                      (param_1,local_88,param_3,uVar3,(longlong)param_4,(longlong)param_5,&local_90)
    ;
    if (iVar2 < 0) {
      if (3 < DAT_00016000) {
        local_98 = CONCAT44(local_98._4_4_,iVar2);
LAB_00005fdf:
        local_54 = 0;
        local_60 = &local_98;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(param_1,&DAT_00013c91);
      }
LAB_00006007:
      if (local_90 != 0) {
        BfsDereferencePolicyEntryEx(local_90,'\0');
      }
      goto LAB_00006035;
    }
  }
  else {
    LOCK();
    *(int *)(lVar4 + 0x90) = *(int *)(lVar4 + 0x90) + 1;
    UNLOCK();
    ExReleasePushLockSharedEx(param_3);
    KeLeaveCriticalRegion();
    if (*(int *)(lVar4 + 0x38) == 0x10000001) {
      param_1 = *(dword **)(lVar4 + 0x28);
      KeWaitForSingleObject(param_1,0,0,0);
      if (*(int *)(lVar4 + 0x38) != 0x10000000) {
        if (3 < DAT_00016000) {
          local_98 = CONCAT44(local_98._4_4_,0xc0000001);
          goto LAB_00005fdf;
        }
        goto LAB_00006007;
      }
    }
  }
  LOCK();
  *(undefined8 *)(local_90 + 0x60) = _DAT_fffff78000000014;
  UNLOCK();
  *param_6 = local_90;
LAB_00006035:
  __security_check_cookie(local_50 ^ (ulonglong)auStackY_d8);
  return;
}

