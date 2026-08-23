/* 3D preview of STL files on bare WebGL - no external libraries, which is what
   lets the page work under a strict CSP (script-src 'self'). */

(function () {
  "use strict";

  const VERTEX_SHADER = `
    attribute vec3 aPos;
    attribute vec3 aNormal;
    uniform mat4 uModel;
    uniform mat4 uProj;
    varying vec3 vNormal;
    varying vec3 vPos;
    void main() {
      vec4 world = uModel * vec4(aPos, 1.0);
      vNormal = mat3(uModel) * aNormal;
      vPos = world.xyz;
      gl_Position = uProj * world;
    }`;

  const FRAGMENT_SHADER = `
    precision mediump float;
    varying vec3 vNormal;
    varying vec3 vPos;
    void main() {
      vec3 n = normalize(vNormal);
      vec3 light = normalize(vec3(0.4, 0.7, 1.0));
      float diffuse = max(dot(n, light), 0.0);
      float rim = pow(1.0 - max(dot(n, normalize(-vPos)), 0.0), 2.0);
      vec3 base = vec3(0.42, 0.60, 0.85);
      vec3 color = base * (0.25 + 0.75 * diffuse) + vec3(0.18, 0.28, 0.45) * rim;
      gl_FragColor = vec4(color, 1.0);
    }`;

  /* --- STL parsing --- */

  function parseSTL(buffer) {
    const view = new DataView(buffer);
    if (buffer.byteLength >= 84) {
      const count = view.getUint32(80, true);
      if (buffer.byteLength === 84 + count * 50 && count > 0) {
        return parseBinary(view, count);
      }
    }
    return parseAscii(new TextDecoder().decode(buffer));
  }

  function parseBinary(view, count) {
    const positions = new Float32Array(count * 9);
    const normals = new Float32Array(count * 9);
    let offset = 84;
    for (let i = 0; i < count; i++) {
      const nx = view.getFloat32(offset, true);
      const ny = view.getFloat32(offset + 4, true);
      const nz = view.getFloat32(offset + 8, true);
      offset += 12;
      for (let v = 0; v < 3; v++) {
        const base = i * 9 + v * 3;
        positions[base] = view.getFloat32(offset, true);
        positions[base + 1] = view.getFloat32(offset + 4, true);
        positions[base + 2] = view.getFloat32(offset + 8, true);
        normals[base] = nx;
        normals[base + 1] = ny;
        normals[base + 2] = nz;
        offset += 12;
      }
      offset += 2; // attribute byte count
    }
    return { positions: positions, normals: normals, triangles: count };
  }

  function parseAscii(text) {
    const positions = [];
    const normals = [];
    let normal = [0, 0, 1];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const parts = lines[i].trim().split(/\s+/);
      if (parts[0] === "facet" && parts[1] === "normal") {
        normal = [parseFloat(parts[2]), parseFloat(parts[3]), parseFloat(parts[4])];
      } else if (parts[0] === "vertex") {
        positions.push(parseFloat(parts[1]), parseFloat(parts[2]), parseFloat(parts[3]));
        normals.push(normal[0], normal[1], normal[2]);
      }
    }
    return {
      positions: new Float32Array(positions),
      normals: new Float32Array(normals),
      triangles: positions.length / 9
    };
  }

  /* --- Minimal 4x4 matrix algebra --- */

  function multiply(a, b) {
    const out = new Float32Array(16);
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        out[c * 4 + r] =
          a[0 * 4 + r] * b[c * 4 + 0] +
          a[1 * 4 + r] * b[c * 4 + 1] +
          a[2 * 4 + r] * b[c * 4 + 2] +
          a[3 * 4 + r] * b[c * 4 + 3];
      }
    }
    return out;
  }

  function perspective(fovY, aspect, near, far) {
    const f = 1 / Math.tan(fovY / 2);
    const out = new Float32Array(16);
    out[0] = f / aspect;
    out[5] = f;
    out[10] = (far + near) / (near - far);
    out[11] = -1;
    out[14] = (2 * far * near) / (near - far);
    return out;
  }

  function rotationY(angle) {
    const c = Math.cos(angle), s = Math.sin(angle);
    return new Float32Array([c, 0, -s, 0, 0, 1, 0, 0, s, 0, c, 0, 0, 0, 0, 1]);
  }

  function rotationX(angle) {
    const c = Math.cos(angle), s = Math.sin(angle);
    return new Float32Array([1, 0, 0, 0, 0, c, s, 0, 0, -s, c, 0, 0, 0, 0, 1]);
  }

  function translation(x, y, z) {
    return new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, x, y, z, 1]);
  }

  function scaling(s) {
    return new Float32Array([s, 0, 0, 0, 0, s, 0, 0, 0, 0, s, 0, 0, 0, 0, 1]);
  }

  /* --- Viewer --- */

  function STLViewer(holder) {
    this.holder = holder;
    this.canvas = document.createElement("canvas");
    holder.insertBefore(this.canvas, holder.firstChild);
    this.gl = this.canvas.getContext("webgl", { antialias: true, alpha: false });
    this.yaw = 0.6;
    this.pitch = -0.5;
    this.zoom = 1;
    this.count = 0;
    this.dragging = false;

    if (this.gl) {
      this.setupGL();
      this.bindInput();
    }
  }

  STLViewer.prototype.supported = function () {
    return !!this.gl;
  };

  STLViewer.prototype.setupGL = function () {
    const gl = this.gl;
    const compile = function (type, source) {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      return shader;
    };
    const program = gl.createProgram();
    gl.attachShader(program, compile(gl.VERTEX_SHADER, VERTEX_SHADER));
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER, FRAGMENT_SHADER));
    gl.linkProgram(program);
    gl.useProgram(program);

    this.program = program;
    this.aPos = gl.getAttribLocation(program, "aPos");
    this.aNormal = gl.getAttribLocation(program, "aNormal");
    this.uModel = gl.getUniformLocation(program, "uModel");
    this.uProj = gl.getUniformLocation(program, "uProj");
    this.posBuffer = gl.createBuffer();
    this.normalBuffer = gl.createBuffer();

    gl.enable(gl.DEPTH_TEST);
    gl.clearColor(0.039, 0.051, 0.071, 1);
  };

  STLViewer.prototype.bindInput = function () {
    const self = this;
    let lastX = 0, lastY = 0;

    this.canvas.addEventListener("pointerdown", function (event) {
      self.dragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
      self.canvas.setPointerCapture(event.pointerId);
    });
    this.canvas.addEventListener("pointermove", function (event) {
      if (!self.dragging) return;
      self.yaw += (event.clientX - lastX) * 0.01;
      self.pitch += (event.clientY - lastY) * 0.01;
      self.pitch = Math.max(-1.5, Math.min(1.5, self.pitch));
      lastX = event.clientX;
      lastY = event.clientY;
      self.draw();
    });
    this.canvas.addEventListener("pointerup", function () { self.dragging = false; });
    this.canvas.addEventListener("wheel", function (event) {
      event.preventDefault();
      self.zoom *= event.deltaY > 0 ? 1.1 : 0.9;
      self.zoom = Math.max(0.3, Math.min(6, self.zoom));
      self.draw();
    }, { passive: false });

    window.addEventListener("resize", function () { self.draw(); });
  };

  STLViewer.prototype.load = function (buffer) {
    const mesh = parseSTL(buffer);
    if (!mesh.triangles) throw new Error(window.I18N.t("viewer.parseFailed"));

    // Centre the mesh and normalise scale so every model fills the frame.
    const p = mesh.positions;
    let minX = Infinity, minY = Infinity, minZ = Infinity;
    let maxX = -Infinity, maxY = -Infinity, maxZ = -Infinity;
    for (let i = 0; i < p.length; i += 3) {
      if (p[i] < minX) minX = p[i];
      if (p[i] > maxX) maxX = p[i];
      if (p[i + 1] < minY) minY = p[i + 1];
      if (p[i + 1] > maxY) maxY = p[i + 1];
      if (p[i + 2] < minZ) minZ = p[i + 2];
      if (p[i + 2] > maxZ) maxZ = p[i + 2];
    }
    this.center = [(minX + maxX) / 2, (minY + maxY) / 2, (minZ + maxZ) / 2];
    const extent = Math.max(maxX - minX, maxY - minY, maxZ - minZ) || 1;
    this.scale = 2 / extent;

    const gl = this.gl;
    gl.bindBuffer(gl.ARRAY_BUFFER, this.posBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, mesh.positions, gl.STATIC_DRAW);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.normalBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, mesh.normals, gl.STATIC_DRAW);
    this.count = mesh.positions.length / 3;

    this.draw();
    return mesh.triangles;
  };

  STLViewer.prototype.draw = function () {
    if (!this.gl || !this.count) return;
    const gl = this.gl;
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(1, Math.floor(this.holder.clientWidth * ratio));
    const height = Math.max(1, Math.floor(this.holder.clientHeight * ratio));
    if (this.canvas.width !== width || this.canvas.height !== height) {
      this.canvas.width = width;
      this.canvas.height = height;
    }
    gl.viewport(0, 0, width, height);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    let model = translation(-this.center[0], -this.center[1], -this.center[2]);
    model = multiply(scaling(this.scale), model);
    model = multiply(rotationY(this.yaw), model);
    model = multiply(rotationX(this.pitch), model);
    model = multiply(translation(0, 0, -5 * this.zoom), model);

    gl.uniformMatrix4fv(this.uModel, false, model);
    gl.uniformMatrix4fv(
      this.uProj, false, perspective(Math.PI / 4, width / height, 0.1, 100)
    );

    gl.bindBuffer(gl.ARRAY_BUFFER, this.posBuffer);
    gl.enableVertexAttribArray(this.aPos);
    gl.vertexAttribPointer(this.aPos, 3, gl.FLOAT, false, 0, 0);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.normalBuffer);
    gl.enableVertexAttribArray(this.aNormal);
    gl.vertexAttribPointer(this.aNormal, 3, gl.FLOAT, false, 0, 0);

    gl.drawArrays(gl.TRIANGLES, 0, this.count);
  };

  window.STLViewer = STLViewer;
})();
