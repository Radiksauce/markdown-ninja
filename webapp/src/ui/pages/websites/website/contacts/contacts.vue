<template>
  <div class="flex-col">

    <div class="mt-2 flex flex-row justify-between items-center mb-4">
      <div class="px-4 sm:px-6 md:px-0">
        <h1 class="text-3xl font-extrabold text-gray-900">Contacts</h1>
      </div>

      <div class="flex">
        <Menu as="div" class="relative inline-block text-left">
            <div>
              <MenuButton class="inline-flex w-full justify-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-xs ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
                <!-- Options -->
                <EllipsisVerticalIcon class="h-5 w-5 text-gray-700" aria-hidden="true" />
              </MenuButton>
            </div>

            <transition enter-active-class="transition ease-out duration-100" enter-from-class="transform opacity-0 scale-95" enter-to-class="transform opacity-100 scale-100" leave-active-class="transition ease-in duration-75" leave-from-class="transform opacity-100 scale-100" leave-to-class="transform opacity-0 scale-95">
              <MenuItems class="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-gray-300 focus:outline-none">
                <div class="py-1">
                  <MenuItem v-slot="{ active }" @click="openImportContactsDialog()">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Import Contacts
                    </span>
                  </MenuItem>
                  <MenuItem v-slot="{ active }" @click="openExportContactsDialog()">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Export Contacts
                    </span>
                  </MenuItem>
                </div>
              </MenuItems>
            </transition>
          </Menu>
      </div>
    </div>

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex flex-row content-center space-x-2">
      <sl-input :value="searchQuery" @input="searchQuery = $event.target.value" type="text" @keyup.enter="fetchData()"
        placeholder="Search contacts" />

        <RouterLink :to="newContactUrl">
          <sl-button variant="primary">
            <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
            New Contact
          </sl-button>
        </RouterLink>
    </div>

    <div class="flex">
      <ContactsList :contacts="contacts" @delete="onDeleteContactClicked" />
    </div>

  </div>

  <DeleteDialog v-model="showDeleteContactDialog" :error="deleteContactDialogError"
    :title="deleteContactDialogTitle" :message="deleteContactDialogMessage" :loading="deleteContactDialogLoading"
    @delete="deleteContact"
  />

  <ImportContactsDialog v-model="showImportContactsDialog" :website-id="websiteId" @imported="fetchData()" />

  <ExportContactsDialog v-model="showExportContactsDialog" :website-id="websiteId" />
</template>

<script lang="ts" setup>
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import ContactsList from '@/ui/components/contacts/contacts_list.vue';
import type { Contact, ListContactsInput } from '@/api/model';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import { useMdninja } from '@/api/mdninja';
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/vue'
import { EllipsisVerticalIcon } from '@heroicons/vue/24/outline'
import ImportContactsDialog from '@/ui/components/contacts/import_contacts_dialog.vue';
import ExportContactsDialog from '@/ui/components/contacts/export_contacts_dialog.vue';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const newContactUrl = `./contacts/new`;
const websiteId = $route.params.website_id as string;
const deleteContactDialogTitle = 'Delete Contact';
const deleteContactDialogMessage = 'Are you sure you want to delete this Contact? This action cannot be undone.';

let contacts: Ref<Contact[]> = ref([]);
let loading = ref(false);
let error = ref('');

let showDeleteContactDialog = ref(false);
let deleteContactDialogError = ref('');
let deleteContactDialogLoading = ref(false);
let contactIdToDelete: Ref<string | null> = ref(null);
let showImportContactsDialog = ref(false);
let showExportContactsDialog = ref(false);
let searchQuery = ref('');

// computed

// watch

// functions
function openImportContactsDialog() {
  showImportContactsDialog.value = true;
}

function openExportContactsDialog() {
  showExportContactsDialog.value = true;
}

async function fetchData() {
  loading.value = true;
  error.value = '';

  const query = searchQuery.value.trim();
  const input: ListContactsInput = {
    website_id: websiteId,
    query: query === "" ? undefined : query,
  };

  try {
    const res = await $mdninja.listContacts(input);
    contacts.value = res.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onDeleteContactClicked(contact: Contact) {
  contactIdToDelete.value = contact.id;
  showDeleteContactDialog.value = true;
}

async function deleteContact() {
  deleteContactDialogLoading.value = true;
  deleteContactDialogError.value = '';

  try {
    await $mdninja.deleteContact(contactIdToDelete.value!);
    contacts.value = contacts.value.filter((t: Contact) => t.id !== contactIdToDelete.value);
    contactIdToDelete.value = null;
    showDeleteContactDialog.value = false;
  } catch (err: any) {
    deleteContactDialogError.value = err.message;
  } finally {
    deleteContactDialogLoading.value = false;
  }
}
</script>
