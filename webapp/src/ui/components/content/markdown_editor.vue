<template>
  <div ref="editor" class="w-full h-full"></div>
  <!-- <sl-textarea :value="markdown" @input="markdown = $event.target.value" @sl-input="onInput"
    rows="30" :placeholder="placeholder" spellcheck :disabled="disabled" :label="label" /> -->
</template>

<script lang="ts" setup>
import { ref, type PropType, onMounted, watch } from 'vue';
import { minimalSetup } from 'codemirror';
import { EditorView, keymap, placeholder } from "@codemirror/view"
import { markdown as markdownPlugin, markdownLanguage } from '@codemirror/lang-markdown';
import {indentWithTab} from "@codemirror/commands";
import {Compartment, EditorState} from "@codemirror/state";
// const { EditorState } = (() => import("@codemirror/state")) as any;
// import { languages } from '@codemirror/language-data';

// codemirror docs:
// - https://codemirror.net/examples/config/
// - https://codemirror.net/examples/bundle/


// props
const markdown = defineModel({
  type: String as PropType<string>,
  required: true,
});

const props = defineProps({
  placeholder: {
    type: String as PropType<string>,
    required: false,
    default: 'What are you thinking about today?'
  },
  disabled: {
    type: Boolean as PropType<boolean>,
    required: false,
    default: false,
  },
  label: {
    type: String as PropType<string>,
    required: false,
    default: null,
  }
});

// events
const $emit = defineEmits(['update:modelValue']);

// composables

// lifecycle
onMounted(() => {
  const state = EditorState.create({
    doc: markdown.value,
    extensions: [
      // basicSetup,
      minimalSetup,
      keymap.of([indentWithTab]),
      placeholder(props.placeholder),
      markdownPlugin({
        base: markdownLanguage,
        // codeLanguages: languages,
      }),
      EditorState.allowMultipleSelections.of(true),
      EditorView.lineWrapping,
      EditorView.updateListener.of((update) => {
        if (update.changes) {
          // Update the Vue ref whenever the content changes
          markdown.value = codeMirrorView!.state.doc.toString();
        }
      }),
      EditorView.theme({
        ".cm-content, .cm-gutter": {minHeight: "300px"},
        // ".cm-scroller": {overflow: "auto"}
      }),
      editableCompartment.of(EditorView.editable.of(!props.disabled)),
    ],
  });

  codeMirrorView = new EditorView({
    state,
    parent: editor.value!,
  });
})

// variables
const editor = ref(null);
let codeMirrorView: EditorView | null = null;
const editableCompartment = new Compartment;

// computed

// watch
watch(() => props.disabled, (to) => {
  codeMirrorView?.dispatch({
    effects: editableCompartment.reconfigure(EditorView.editable.of(!to)),
  });
});


// functions
</script>

<style>
.cm-editor {
  border: 1px solid var(--color-neutral-300);
  border-radius: var(--radius-md);
}

.cm-editor.cm-focused {
  outline: none;
  border-color: var(--primary-color);
}

.cm-editor:hover:not(.cm-focused) {
  border-color: var(--color-neutral-400);
}
</style>
