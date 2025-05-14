<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-5">
      <h1 class="text-3xl font-extrabold text-gray-900">Staffs</h1>
    </div>

    <div class="flex rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex">
      <StaffsList :staffs="staffs" @remove="removeStaff" />
    </div>

    <div class="mt-6 px-4 sm:px-6 md:px-0 mb-4">
      <h2 class="text-2xl font-bold text-gray-900">Invitations</h2>
    </div>

    <div class="flex">
      <sl-button variant="primary" @click="openInviteStaffsDialog()">
        <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
        Invite Staff
      </sl-button>
    </div>

    <div class="flex">
      <StaffInvitationsList :invitations="invitations" @delete="deleteInvitation" />
    </div>

  </div>

  <InviteStaffsDialog v-model="showInviteStaffsDialog" :organization-id="organizationId"
    @invited="onStaffsInvited"
  />
</template>

<script lang="ts" setup>
import { useMdninja } from '@/api/mdninja';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import StaffsList from '@/ui/components/organizations/staffs_list.vue'
import type { RemoveStaffInput, Staff, StaffInvitation } from '@/api/model';
import StaffInvitationsList from '@/ui/components/organizations/staff_invitations_list.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import InviteStaffsDialog from '@/ui/components/organizations/invite_staffs_dialog.vue';
import { useStore } from '@/app/store';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();
const $store = useStore();
const $router = useRouter();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const organizationId = $route.params.organization_id as string;

let loading = ref(false);
let error = ref('');
let showInviteStaffsDialog = ref(false);

let staffs: Ref<Staff[]> = ref([]);
let invitations: Ref<StaffInvitation[]> = ref([]);

// computed

// watch

// functions
function openInviteStaffsDialog() {
  showInviteStaffsDialog.value = true;
}

async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const res = await Promise.all([
      $mdninja.getOrganization({ id: organizationId, staffs: true }),
      $mdninja.listStaffInvitationsForOrganization(organizationId),
    ]);
    staffs.value = res[0].staffs!;
    invitations.value = res[1].data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onStaffsInvited(newInvitations: StaffInvitation[]) {
  invitations.value.push(...newInvitations);
  showInviteStaffsDialog.value = false;
}

async function deleteInvitation(invitation: StaffInvitation) {
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

async function removeStaff(staff: Staff) {
  loading.value = true;
  error.value = '';
  const intput: RemoveStaffInput = {
    organization_id: organizationId,
    user_id: staff.user_id,
  }

  try {
    await $mdninja.removeStaff(intput);
    staffs.value = staffs.value.filter((sta) => sta.user_id !== staff.user_id);
    if ($store.userId === staff.user_id) {
      $router.push('/organizations');
    }
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
