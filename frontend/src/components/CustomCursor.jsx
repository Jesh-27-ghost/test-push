import React, { useEffect, useRef, useState } from 'react';

export default function CustomCursor() {
  const innerRef = useRef(null);
  const outerRef = useRef(null);
  const mouse = useRef({ x: 0, y: 0 });
  const inner = useRef({ x: 0, y: 0 });
  const outer = useRef({ x: 0, y: 0 });
  const [hovering, setHovering] = useState(false);
  const [clicking, setClicking] = useState(false);

  useEffect(() => {
    const onMove = (e) => {
      mouse.current.x = e.clientX;
      mouse.current.y = e.clientY;
    };
    const onDown = () => setClicking(true);
    const onUp = () => setClicking(false);

    const onOver = (e) => {
      const t = e.target;
      if (
        t.tagName === 'BUTTON' ||
        t.tagName === 'A' ||
        t.tagName === 'INPUT' ||
        t.tagName === 'TEXTAREA' ||
        t.tagName === 'SELECT' ||
        t.closest('button') ||
        t.closest('a') ||
        t.closest('tr') ||
        t.closest('[role="button"]') ||
        t.dataset.cursor === 'pointer'
      ) {
        setHovering(true);
      }
    };
    const onOut = () => setHovering(false);

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mousedown', onDown);
    window.addEventListener('mouseup', onUp);
    document.addEventListener('mouseover', onOver);
    document.addEventListener('mouseout', onOut);

    let raf;
    const animate = () => {
      inner.current.x += (mouse.current.x - inner.current.x) * 0.3;
      inner.current.y += (mouse.current.y - inner.current.y) * 0.3;
      outer.current.x += (mouse.current.x - outer.current.x) * 0.12;
      outer.current.y += (mouse.current.y - outer.current.y) * 0.12;

      if (innerRef.current) {
        innerRef.current.style.left = `${inner.current.x}px`;
        innerRef.current.style.top = `${inner.current.y}px`;
      }
      if (outerRef.current) {
        outerRef.current.style.left = `${outer.current.x}px`;
        outerRef.current.style.top = `${outer.current.y}px`;
      }
      raf = requestAnimationFrame(animate);
    };
    raf = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mousedown', onDown);
      window.removeEventListener('mouseup', onUp);
      document.removeEventListener('mouseover', onOver);
      document.removeEventListener('mouseout', onOut);
    };
  }, []);

  const innerClass = `custom-cursor-inner${hovering ? ' hovering' : ''}${clicking ? ' clicking' : ''}`;
  const outerClass = `custom-cursor-outer${hovering ? ' hovering' : ''}`;

  return (
    <>
      <div ref={innerRef} className={innerClass} />
      <div ref={outerRef} className={outerClass} />
    </>
  );
}
