#!/usr/bin/env python3
"""
Build a self-contained artifact group.html with all JS modules inlined.

Reads:
  - group.html (template)
  - platform_module.js, utility_module.js (base modules)
  - Stage1_*.js, Stage2_*.js, Stage3_*.js (stage modules)
  - other/Stage*.js (fallback modules)

Outputs:
  - build/group.html (single self-contained HTML file)
"""

import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "build")

# Stage modules to inline and their moduleManager IDs
# These match the names used in getModuleByURL() calls in group.html
STAGE_MODULES = {
    # Stage 1 — WebKit memory corruption
    "Stage1_15.2_15.5_jacurutu": "Stage1_15.2_15.5_jacurutu.js",
    "Stage1_16.2_16.5.1_terrorbird": "Stage1_16.2_16.5.1_terrorbird.js",
    "Stage1_16.6_17.2.1_cassowary": "Stage1_16.6_17.2.1_cassowary.js",
    "Stage1_18.0_18.x_manticore": "Stage1_18.0_18.x_manticore.js",
    "Stage1_26.0_26.x_chimera": "Stage1_26.0_26.x_chimera.js",
    # Stage 2 — PAC bypass
    "Stage2_16.3_16.5.1_seedbell": "Stage2_16.3_16.5.1_seedbell.js",
    "Stage2_16.6_16.7.12_seedbell": "Stage2_16.6_16.7.12_seedbell.js",
    "Stage2_16.6_17.2.1_seedbell_pre": "Stage2_16.6_17.2.1_seedbell_pre.js",
    "Stage2_17.0_17.2.1_seedbell": "Stage2_17.0_17.2.1_seedbell.js",
    "Stage2_18.0_18.x_thornvine": "Stage2_18.0_18.x_thornvine.js",
    "Stage2_26.0_26.x_ironroot": "Stage2_26.0_26.x_ironroot.js",
    # Stage 3 — Sandbox escape
    "Stage3_VariantB": "Stage3_VariantB.js",
}

# Modules from other/ directory (fallback variants)
OTHER_MODULES = {
    "Stage1_15.6_16.1.2_bluebird": "other/Stage1_15.6_16.1.2_bluebird.js",
    "Stage2_15.0_16.2_breezy15": "other/Stage2_15.0_16.2_breezy15.js",
    "Stage2_13.0_14.x_breezy": "other/Stage2_13.0_14.x_breezy.js",
    "Stage3_VariantA": "other/Stage3_VariantA.js",
}


def read_file(path):
    with open(os.path.join(BASE_DIR, path), "r", encoding="utf-8") as f:
        return f.read()


def build_inline_modules_block(modules_dict):
    """
    Build JS code that pre-registers stage modules in the moduleManager.

    Stage files use `return r;` at the end, so wrapping them in a function
    makes them compatible with the moduleManager's factory pattern:
      MM["moduleId"] = function() { <stage code> }
    """
    blocks = []
    for module_id, file_path in modules_dict.items():
        full_path = os.path.join(BASE_DIR, file_path)
        if not os.path.exists(full_path):
            print(f"  WARNING: {file_path} not found, skipping")
            continue

        code = read_file(file_path)
        # Escape </script> in inline code to avoid premature HTML close
        code = code.replace("</script>", "<\\/script>")

        blocks.append(
            f'        // Inlined from {file_path}\n'
            f'        globalThis.moduleManager.evalCode("{module_id}", function() {{\n'
            f'{code}\n'
            f'        }});\n'
        )
        print(f"  Inlined: {module_id} ({file_path})")

    return "\n".join(blocks)


def build():
    print("=" * 60)
    print("Building self-contained artifact group.html")
    print("=" * 60)

    # Read template
    html = read_file("group.html")

    # --- Step 1: Inline platform_module.js and utility_module.js ---
    print("\n[1] Inlining base modules...")

    platform_js = read_file("platform_module.js")
    utility_js = read_file("utility_module.js")

    # Replace <script src="platform_module.js"></script> with inline
    html = html.replace(
        '<script src="platform_module.js"></script>',
        f'<script type="text/javascript">\n{utility_js}\n</script>\n'
        f'    <script type="text/javascript">\n{platform_js}\n</script>'
    )
    # Remove the separate utility_module.js script tag
    html = html.replace(
        '    <script src="utility_module.js"></script>\n', ''
    )
    print("  Inlined: utility_module.js")
    print("  Inlined: platform_module.js")

    # --- Step 2: Inline stage modules ---
    print("\n[2] Inlining stage modules...")

    stage_code = build_inline_modules_block(STAGE_MODULES)

    print("\n[3] Inlining fallback modules from other/...")
    other_code = build_inline_modules_block(OTHER_MODULES)

    all_inline_code = stage_code + "\n" + other_code

    # Insert the inlined modules right after moduleManager initialization
    # (after the line `globalThis.moduleManager.setSalt(...)`)
    salt_line = 'globalThis.moduleManager.setSalt("cecd08aa6ff548c2");'
    insertion_point = html.find(salt_line)
    if insertion_point == -1:
        print("  ERROR: Could not find setSalt insertion point")
        return
    insertion_point = html.find("\n", insertion_point) + 1

    html = (
        html[:insertion_point]
        + "\n        // ============================================================\n"
        + "        // Inlined Stage Modules (self-contained build)\n"
        + "        // ============================================================\n\n"
        + all_inline_code
        + "\n"
        + html[insertion_point:]
    )

    # --- Step 3: Write output ---
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "group.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"\n[4] Output: {output_path}")
    print(f"    Size: {size_kb:.1f} KB")

    # Count inlined modules
    total_modules = 2  # platform + utility
    for mod_id, path in {**STAGE_MODULES, **OTHER_MODULES}.items():
        if os.path.exists(os.path.join(BASE_DIR, path)):
            total_modules += 1

    print(f"    Modules inlined: {total_modules}")
    print(f"\n{'=' * 60}")
    print("BUILD COMPLETE")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    build()
