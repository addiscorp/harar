# Seam Contract IR

Seam IR is a small serialized contract algebra for wire-crossing shapes. It is
not a source language type system. Extractors derive this document from real
compiler type information, and checkers compare documents across language
boundaries.

The current format is `seam.contract@1`.

```json
{
  "format": "seam.contract@1",
  "name": "handle",
  "version": 1,
  "boundaries": [
    { "function": "handle", "request": "Request", "response": "Response" }
  ],
  "definitions": [
    {
      "kind": "record",
      "name": "Request",
      "fields": {
        "method": { "kind": "primitive", "name": "String" }
      }
    },
    {
      "kind": "enum",
      "name": "HandlerState",
      "variants": [
        { "name": "Ready", "fields": {} }
      ]
    }
  ]
}
```

Supported type expressions are `Primitive(String|Int|Bool|Bytes)`,
`Named(name)`, `Option<T>`, `List<T>`, and `Map<K,V>`. Records contain named
fields. Enums contain named variants, each with optional named payload fields,
so consumers can perform exhaustiveness checks against producer output.
