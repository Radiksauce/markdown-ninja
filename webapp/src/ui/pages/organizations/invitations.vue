<template>
  <div class="flex-1">

    <div class="px-4 sm:px-6 md:px-0">
      <h1 class="text-3xl font-extrabold text-gray-900">Invitations</h1>
    </div>

    <div class="flex">
      <UserInvitationsList :invitations="invitations"
        @decline="delcineInvitation" @accept="acceptInvitation"
      />
    </div>

  </div>
</template>

<script lang="ts" setup>
import { useMdninja } from '@/api/mdninja';
import type { UserInvitation } from '@/api/model';
import UserInvitationsList from '@/ui/components/kernel/user_invitations_list.vue';
import { onBeforeMount, ref, type Ref } from 'vue';

// props

// events

// composables
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => fetchData());


// variables
let loading = ref(false);
let error = ref('');

let invitations: Ref<UserInvitation[]> = ref([]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const res = await $mdninja.listUserInvitations();
    invitations.value = res.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function acceptInvitation(invitation: UserInvitation) {
  loading.value = true;
  error.value = '';

  try {
    await $mdninja.acceptStaffInvitation(invitation.id);
    invitations.value = invitations.value.filter((invit) => invit.id !== invitation.id);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function delcineInvitation(invitation: UserInvitation) {
  loading.value = true;
  error.value = '';

  try {
    await $mdninja.deleteStaffInvitation(invitation.id);
    invitations.value = invitations.value.filter((invit) => invit.id !== invitation.id);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
