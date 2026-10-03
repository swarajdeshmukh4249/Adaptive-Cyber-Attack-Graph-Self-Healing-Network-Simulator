const { memo, useCallback, useEffect, useRef } = React;

const GlowingEffect = memo(function GlowingEffect({
  blur = 0,
  inactiveZone = 0.7,
  proximity = 0,
  spread = 20,
  variant = "default",
  glow = false,
  className = "",
  movementDuration = 2,
  borderWidth = 1,
  disabled = true,
}) {
  const containerRef = useRef(null);
  const lastPosition = useRef({ x: 0, y: 0 });
  const animationFrameRef = useRef(0);

  const handleMove = useCallback((e) => {
    if (!containerRef.current) return;

    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current);
    }

    animationFrameRef.current = requestAnimationFrame(() => {
      const element = containerRef.current;
      if (!element) return;

      const { left, top, width, height } = element.getBoundingClientRect();
      const mouseX = e?.x ?? lastPosition.current.x;
      const mouseY = e?.y ?? lastPosition.current.y;

      if (e) {
        lastPosition.current = { x: mouseX, y: mouseY };
      }

      const center = [left + width * 0.5, top + height * 0.5];
      const distanceFromCenter = Math.hypot(mouseX - center[0], mouseY - center[1]);
      const inactiveRadius = 0.5 * Math.min(width, height) * inactiveZone;

      if (distanceFromCenter < inactiveRadius) {
        element.style.setProperty("--active", "0");
        return;
      }

      const isActive = mouseX > left - proximity &&
        mouseX < left + width + proximity &&
        mouseY > top - proximity &&
        mouseY < top + height + proximity;

      element.style.setProperty("--active", isActive ? "1" : "0");

      if (!isActive) return;

      const currentAngle = parseFloat(element.style.getPropertyValue("--start")) || 0;
      let targetAngle = (180 * Math.atan2(mouseY - center[1], mouseX - center[0])) / Math.PI + 90;

      const angleDiff = ((targetAngle - currentAngle + 180) % 360) - 180;
      const newAngle = currentAngle + angleDiff;

      if (window.Motion && window.Motion.animate) {
        window.Motion.animate(currentAngle, newAngle, {
          duration: movementDuration,
          ease: [0.16, 1, 0.3, 1],
          onUpdate: (value) => {
            element.style.setProperty("--start", String(value));
          },
        });
      }
    });
  }, [inactiveZone, proximity, movementDuration]);

  useEffect(() => {
    if (disabled) return;

    const handleScroll = () => handleMove();
    const handlePointerMove = (e) => handleMove(e);

    window.addEventListener("scroll", handleScroll, { passive: true });
    document.body.addEventListener("pointermove", handlePointerMove, { passive: true });

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
      window.removeEventListener("scroll", handleScroll);
      document.body.removeEventListener("pointermove", handlePointerMove);
    };
  }, [handleMove, disabled]);

  const gradientStyle = variant === "white"
    ? "repeating-conic-gradient(from 236.84deg at 50% 50%, var(--black), var(--black) calc(25% / var(--repeating-conic-gradient-times)))"
    : variant === "mono"
    ? "radial-gradient(circle, #ffffff 10%, #ffffff00 20%), repeating-conic-gradient(from 236.84deg at 50% 50%, #ffffff 0%, #737373 calc(50% / var(--repeating-conic-gradient-times)), #ffffff calc(100% / var(--repeating-conic-gradient-times)))"
    : variant === "subtle"
    ? "radial-gradient(circle, #60a5fa 10%, #60a5fa00 20%), radial-gradient(circle at 40% 40%, #94a3b8 5%, #94a3b800 15%), repeating-conic-gradient(from 236.84deg at 50% 50%, #60a5fa 0%, #cbd5e1 calc(50% / var(--repeating-conic-gradient-times)), #60a5fa calc(100% / var(--repeating-conic-gradient-times)))"
    : variant === "cyber"
    ? "radial-gradient(circle, #22d3ee 10%, #22d3ee00 20%), radial-gradient(circle at 40% 40%, #f43f5e 5%, #f43f5e00 15%), radial-gradient(circle at 60% 60%, #22c55e 10%, #22c55e00 20%), radial-gradient(circle at 40% 60%, #a855f7 10%, #a855f700 20%), repeating-conic-gradient(from 236.84deg at 50% 50%, #22d3ee 0%, #f43f5e calc(25% / var(--repeating-conic-gradient-times)), #22c55e calc(50% / var(--repeating-conic-gradient-times)), #a855f7 calc(75% / var(--repeating-conic-gradient-times)), #22d3ee calc(100% / var(--repeating-conic-gradient-times)))"
    :"radial-gradient(circle, #dd7bbb 10%, #dd7bbb00 20%), radial-gradient(circle at 40% 40%, #d79f1e 5%, #d79f1e00 15%), radial-gradient(circle at 60% 60%, #5a922c 10%, #5a922c00 20%), radial-gradient(circle at 40% 60%, #4c7894 10%, #4c789400 20%), repeating-conic-gradient(from 236.84deg at 50% 50%, #dd7bbb 0%, #d79f1e calc(25% / var(--repeating-conic-gradient-times)), #5a922c calc(50% / var(--repeating-conic-gradient-times)), #4c7894 calc(75% / var(--repeating-conic-gradient-times)), #dd7bbb calc(100% / var(--repeating-conic-gradient-times)))";

  return React.createElement(React.Fragment, null,
    React.createElement("div", {
      className: cn(
        "pointer-events-none absolute -inset-px hidden rounded-[inherit] border opacity-0 transition-opacity",
        glow && "opacity-100",
        variant === "white" && "border-white",
        disabled && "!block"
      )
    }),
    React.createElement("div", {
      ref: containerRef,
      style: {
        "--blur": `${blur}px`,
        "--spread": spread,
        "--start": "0",
        "--active": "0",
        "--glowingeffect-border-width": `${borderWidth}px`,
        "--repeating-conic-gradient-times": "5",
        "--gradient": gradientStyle
      },
      className: cn(
        "pointer-events-none absolute inset-0 rounded-[inherit] opacity-100 transition-opacity",
        glow && "opacity-100",
        blur > 0 && "blur-[var(--blur)]",
        className,
        disabled && "!hidden"
      )
    },
      React.createElement("div", {
        className: cn(
          "glow rounded-[inherit]",
          'after:content-[""] after:rounded-[inherit] after:absolute after:inset-[calc(-1*var(--glowingeffect-border-width))]',
          "after:[border:var(--glowingeffect-border-width)_solid_transparent]",
          "after:[background:var(--gradient)] after:[background-attachment:fixed]",
          "after:opacity-[var(--active)] after:transition-opacity after:duration-300",
          "after:[mask-clip:padding-box,border-box]",
          "after:[mask-composite:intersect]",
          "after:[mask-image:linear-gradient(#0000,#0000),conic-gradient(from_calc((var(--start)-var(--spread))*1deg),#00000000_0deg,#fff,#00000000_calc(var(--spread)*2deg))]"
        )
      })
    )
  );
});