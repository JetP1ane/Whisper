/**
 * Whisper icon — centered amber bar flanked by mirrored fading
 * gray waveform bars. The black rounded-rect background is rendered
 * unconditionally but hidden in light mode via a CSS rule keyed on
 * `:root.light` (see globals.css). Using CSS instead of a React state
 * read avoids the per-component-state fragmentation of `useTheme()` —
 * every NoctisOwl instance reacts to a theme toggle without needing
 * to be in the same React subtree as the theme button.
 */
export function NoctisOwl({
  size = 16,
  className = "",
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 1024 1024"
      className={className}
      aria-label="Whisper"
      role="img"
    >
      {/* Black rounded-rect background — hidden in light mode by CSS. */}
      <g className="whisper-icon-tile">
        <rect width="1024" height="1024" rx="220" fill="#000000" />
        <rect
          x="1.5"
          y="1.5"
          width="1021"
          height="1021"
          rx="218.5"
          stroke="#151515"
          strokeWidth="3"
        />
      </g>

      {/* Waveform bars */}
      <rect x="173" y="456" width="50" height="114" rx="25" fill="#D7D7D7" />
      <rect x="274" y="389" width="50" height="246" rx="25" fill="#BDBDBD" />
      <rect x="380" y="309" width="50" height="408" rx="25" fill="#8F8F8F" />

      {/* Center amber bar */}
      <rect x="486" y="222" width="52" height="580" rx="26" fill="#F6B32D" />

      <rect x="594" y="309" width="50" height="408" rx="25" fill="#8F8F8F" />
      <rect x="700" y="389" width="50" height="246" rx="25" fill="#BDBDBD" />
      <rect x="801" y="456" width="50" height="114" rx="25" fill="#D7D7D7" />
    </svg>
  );
}
