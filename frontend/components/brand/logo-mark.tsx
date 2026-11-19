/** SanitialX mark: a shield holding a radar sweep and a detected threat. `simple` drops the fine rings for small sizes. */
export function LogoMark({ size = 32, simple = false }: { size?: number; simple?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label="SanitialX" fill="none">
      <defs>
        <linearGradient id="sx-brand-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#12d8ff" />
          <stop offset="1" stopColor="#278cff" />
        </linearGradient>
      </defs>
      <path
        d="M32 4 54 12v18c0 14-10 24-22 30C20 54 10 44 10 30V12z"
        fill={simple ? 'none' : '#061421'}
        stroke="url(#sx-brand-grad)"
        strokeWidth={simple ? 3.4 : 2.6}
        strokeLinejoin="round"
      />
      {simple ? (
        <>
          <circle cx="32" cy="32" r="8" stroke="#12d8ff" strokeWidth="3" />
          <path d="M32 32 46 21" stroke="#12d8ff" strokeWidth="4" strokeLinecap="round" />
        </>
      ) : (
        <>
          <circle cx="32" cy="32" r="6" stroke="#12d8ff" strokeWidth="2" />
          <circle cx="32" cy="32" r="12" stroke="#12d8ff" strokeOpacity=".53" strokeWidth="2" />
          <circle cx="32" cy="32" r="18" stroke="#12d8ff" strokeOpacity=".27" strokeWidth="2" />
          <path d="M32 32 47 20A18 18 0 0 1 50 32Z" fill="#12d8ff" fillOpacity=".33" />
          <path d="M32 32 47 20" stroke="#12d8ff" strokeWidth="3" strokeLinecap="round" />
          <circle cx="41" cy="40" r="2.6" fill="#ff405c" />
        </>
      )}
    </svg>
  );
}
