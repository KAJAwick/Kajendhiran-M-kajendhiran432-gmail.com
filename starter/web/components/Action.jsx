import React from 'react';

// A permission-gated element.
//
// PRESENCE, NOT STATE (UI-INVENTORY.md §1).
//
// If the caller holds the permission, the element is rendered with data-permission and
// data-state="unlocked". If they do not, it is NOT RENDERED AT ALL — there is no disabled
// state. A permission console should not advertise actions a person cannot take.
//
// Two invariants this component exists to uphold:
//
//   1. The decision comes from the SERVER's resolved entry for this permission. There is no
//      role -> permission logic here and there must never be (PERMISSIONS.md §8.3). If the
//      server says deny, this component returns null — and the hidden architecture test
//      asserts exactly that.
//
//   2. Hiding is presentation, not enforcement. Whatever this component chooses to render,
//      the API independently refuses the action. That half is asserted server-side.
export default function Action({ permission, entry, onClick, children, busy = false, testid }) {
  if (entry?.effect !== 'allow') return null;

  return (
    <button
      className="act"
      data-testid={testid}
      data-permission={permission}
      data-state="unlocked"
      data-source={entry?.source ?? ''}
      disabled={busy}
      onClick={onClick}
      title={`allowed by ${entry.source}`}
    >
      {children}
    </button>
  );
}
