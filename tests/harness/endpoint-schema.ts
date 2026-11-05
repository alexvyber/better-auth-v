// Transport schema structure only. V decides projection, merging and requiredness.
// Never parse values, call isOptional/toJSONSchema, or read defaultValue/catchValue:
// those can execute application factories during documentation generation.
export function endpointSchema(value: unknown, depth = 0): string | undefined {
  if (!value) return undefined;
  return JSON.stringify(describe(value, depth));
}
function describe(value: any, depth: number): Record<string, unknown> {
  if (depth > 64) throw new Error('Endpoint schema nesting exceeds 64');
  const definition = value?._zod?.def;
  if (!definition) throw new Error('Endpoint documentation requires a Zod schema descriptor');
  const node: Record<string, unknown> = {kind: definition.type, optional: value._zod.optin !== undefined};
  if (value.description !== undefined) node.description = value.description;
  const child = (schema: unknown) => describe(schema, depth + 1);
  switch (definition.type) {
    case 'object': node.properties = Object.fromEntries(Object.entries(definition.shape).map(([name, schema]) => [name, child(schema)])); break;
    case 'record': node.key = child(definition.keyType); node.value = child(definition.valueType); break;
    case 'array': node.element = child(definition.element); break;
    case 'intersection': node.left = child(definition.left); node.right = child(definition.right); break;
    case 'union': node.options = definition.options.map(child); node.inclusive = definition.inclusive !== false; break;
    case 'pipe': node.input = child(definition.in); node.output = child(definition.out); break;
    case 'optional': case 'nullable': case 'default': case 'prefault': case 'nonoptional': case 'catch': case 'readonly': node.inner = child(definition.innerType); break;
    case 'literal': node.values = definition.values; break;
    case 'enum': node.values = Object.values(definition.entries); break;
    case 'string':
      if (value.minLength != null) node.minLength = value.minLength;
      if (value.maxLength != null) node.maxLength = value.maxLength;
      break;
    case 'number': case 'boolean': case 'date': case 'null': case 'undefined': case 'void': case 'unknown': case 'any': case 'transform': break;
    default: throw new Error(`Unsupported endpoint documentation schema: ${definition.type}`);
  }
  return node;
}
