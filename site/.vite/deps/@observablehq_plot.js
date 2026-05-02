import {
  __commonJS,
  __toESM
} from "./chunk-5WRI5ZAA.js";

// node_modules/binary-search-bounds/search-bounds.js
var require_search_bounds = __commonJS({
  "node_modules/binary-search-bounds/search-bounds.js"(exports, module) {
    "use strict";
    function ge(a2, y3, c4, l, h) {
      var i = h + 1;
      while (l <= h) {
        var m = l + h >>> 1, x3 = a2[m];
        var p = c4 !== void 0 ? c4(x3, y3) : x3 - y3;
        if (p >= 0) {
          i = m;
          h = m - 1;
        } else {
          l = m + 1;
        }
      }
      return i;
    }
    function gt(a2, y3, c4, l, h) {
      var i = h + 1;
      while (l <= h) {
        var m = l + h >>> 1, x3 = a2[m];
        var p = c4 !== void 0 ? c4(x3, y3) : x3 - y3;
        if (p > 0) {
          i = m;
          h = m - 1;
        } else {
          l = m + 1;
        }
      }
      return i;
    }
    function lt(a2, y3, c4, l, h) {
      var i = l - 1;
      while (l <= h) {
        var m = l + h >>> 1, x3 = a2[m];
        var p = c4 !== void 0 ? c4(x3, y3) : x3 - y3;
        if (p < 0) {
          i = m;
          l = m + 1;
        } else {
          h = m - 1;
        }
      }
      return i;
    }
    function le(a2, y3, c4, l, h) {
      var i = l - 1;
      while (l <= h) {
        var m = l + h >>> 1, x3 = a2[m];
        var p = c4 !== void 0 ? c4(x3, y3) : x3 - y3;
        if (p <= 0) {
          i = m;
          l = m + 1;
        } else {
          h = m - 1;
        }
      }
      return i;
    }
    function eq(a2, y3, c4, l, h) {
      while (l <= h) {
        var m = l + h >>> 1, x3 = a2[m];
        var p = c4 !== void 0 ? c4(x3, y3) : x3 - y3;
        if (p === 0) {
          return m;
        }
        if (p <= 0) {
          l = m + 1;
        } else {
          h = m - 1;
        }
      }
      return -1;
    }
    function norm(a2, y3, c4, l, h, f) {
      if (typeof c4 === "function") {
        return f(a2, y3, c4, l === void 0 ? 0 : l | 0, h === void 0 ? a2.length - 1 : h | 0);
      }
      return f(a2, y3, void 0, c4 === void 0 ? 0 : c4 | 0, l === void 0 ? a2.length - 1 : l | 0);
    }
    module.exports = {
      ge: function(a2, y3, c4, l, h) {
        return norm(a2, y3, c4, l, h, ge);
      },
      gt: function(a2, y3, c4, l, h) {
        return norm(a2, y3, c4, l, h, gt);
      },
      lt: function(a2, y3, c4, l, h) {
        return norm(a2, y3, c4, l, h, lt);
      },
      le: function(a2, y3, c4, l, h) {
        return norm(a2, y3, c4, l, h, le);
      },
      eq: function(a2, y3, c4, l, h) {
        return norm(a2, y3, c4, l, h, eq);
      }
    };
  }
});

// node_modules/interval-tree-1d/interval-tree.js
var require_interval_tree = __commonJS({
  "node_modules/interval-tree-1d/interval-tree.js"(exports, module) {
    "use strict";
    var bounds = require_search_bounds();
    var NOT_FOUND = 0;
    var SUCCESS = 1;
    var EMPTY = 2;
    module.exports = createWrapper;
    function IntervalTreeNode(mid2, left2, right2, leftPoints, rightPoints) {
      this.mid = mid2;
      this.left = left2;
      this.right = right2;
      this.leftPoints = leftPoints;
      this.rightPoints = rightPoints;
      this.count = (left2 ? left2.count : 0) + (right2 ? right2.count : 0) + leftPoints.length;
    }
    var proto = IntervalTreeNode.prototype;
    function copy3(a2, b) {
      a2.mid = b.mid;
      a2.left = b.left;
      a2.right = b.right;
      a2.leftPoints = b.leftPoints;
      a2.rightPoints = b.rightPoints;
      a2.count = b.count;
    }
    function rebuild(node, intervals) {
      var ntree = createIntervalTree(intervals);
      node.mid = ntree.mid;
      node.left = ntree.left;
      node.right = ntree.right;
      node.leftPoints = ntree.leftPoints;
      node.rightPoints = ntree.rightPoints;
      node.count = ntree.count;
    }
    function rebuildWithInterval(node, interval2) {
      var intervals = node.intervals([]);
      intervals.push(interval2);
      rebuild(node, intervals);
    }
    function rebuildWithoutInterval(node, interval2) {
      var intervals = node.intervals([]);
      var idx = intervals.indexOf(interval2);
      if (idx < 0) {
        return NOT_FOUND;
      }
      intervals.splice(idx, 1);
      rebuild(node, intervals);
      return SUCCESS;
    }
    proto.intervals = function(result) {
      result.push.apply(result, this.leftPoints);
      if (this.left) {
        this.left.intervals(result);
      }
      if (this.right) {
        this.right.intervals(result);
      }
      return result;
    };
    proto.insert = function(interval2) {
      var weight = this.count - this.leftPoints.length;
      this.count += 1;
      if (interval2[1] < this.mid) {
        if (this.left) {
          if (4 * (this.left.count + 1) > 3 * (weight + 1)) {
            rebuildWithInterval(this, interval2);
          } else {
            this.left.insert(interval2);
          }
        } else {
          this.left = createIntervalTree([interval2]);
        }
      } else if (interval2[0] > this.mid) {
        if (this.right) {
          if (4 * (this.right.count + 1) > 3 * (weight + 1)) {
            rebuildWithInterval(this, interval2);
          } else {
            this.right.insert(interval2);
          }
        } else {
          this.right = createIntervalTree([interval2]);
        }
      } else {
        var l = bounds.ge(this.leftPoints, interval2, compareBegin);
        var r = bounds.ge(this.rightPoints, interval2, compareEnd);
        this.leftPoints.splice(l, 0, interval2);
        this.rightPoints.splice(r, 0, interval2);
      }
    };
    proto.remove = function(interval2) {
      var weight = this.count - this.leftPoints;
      if (interval2[1] < this.mid) {
        if (!this.left) {
          return NOT_FOUND;
        }
        var rw = this.right ? this.right.count : 0;
        if (4 * rw > 3 * (weight - 1)) {
          return rebuildWithoutInterval(this, interval2);
        }
        var r = this.left.remove(interval2);
        if (r === EMPTY) {
          this.left = null;
          this.count -= 1;
          return SUCCESS;
        } else if (r === SUCCESS) {
          this.count -= 1;
        }
        return r;
      } else if (interval2[0] > this.mid) {
        if (!this.right) {
          return NOT_FOUND;
        }
        var lw = this.left ? this.left.count : 0;
        if (4 * lw > 3 * (weight - 1)) {
          return rebuildWithoutInterval(this, interval2);
        }
        var r = this.right.remove(interval2);
        if (r === EMPTY) {
          this.right = null;
          this.count -= 1;
          return SUCCESS;
        } else if (r === SUCCESS) {
          this.count -= 1;
        }
        return r;
      } else {
        if (this.count === 1) {
          if (this.leftPoints[0] === interval2) {
            return EMPTY;
          } else {
            return NOT_FOUND;
          }
        }
        if (this.leftPoints.length === 1 && this.leftPoints[0] === interval2) {
          if (this.left && this.right) {
            var p = this;
            var n = this.left;
            while (n.right) {
              p = n;
              n = n.right;
            }
            if (p === this) {
              n.right = this.right;
            } else {
              var l = this.left;
              var r = this.right;
              p.count -= n.count;
              p.right = n.left;
              n.left = l;
              n.right = r;
            }
            copy3(this, n);
            this.count = (this.left ? this.left.count : 0) + (this.right ? this.right.count : 0) + this.leftPoints.length;
          } else if (this.left) {
            copy3(this, this.left);
          } else {
            copy3(this, this.right);
          }
          return SUCCESS;
        }
        for (var l = bounds.ge(this.leftPoints, interval2, compareBegin); l < this.leftPoints.length; ++l) {
          if (this.leftPoints[l][0] !== interval2[0]) {
            break;
          }
          if (this.leftPoints[l] === interval2) {
            this.count -= 1;
            this.leftPoints.splice(l, 1);
            for (var r = bounds.ge(this.rightPoints, interval2, compareEnd); r < this.rightPoints.length; ++r) {
              if (this.rightPoints[r][1] !== interval2[1]) {
                break;
              } else if (this.rightPoints[r] === interval2) {
                this.rightPoints.splice(r, 1);
                return SUCCESS;
              }
            }
          }
        }
        return NOT_FOUND;
      }
    };
    function reportLeftRange(arr, hi, cb) {
      for (var i = 0; i < arr.length && arr[i][0] <= hi; ++i) {
        var r = cb(arr[i]);
        if (r) {
          return r;
        }
      }
    }
    function reportRightRange(arr, lo, cb) {
      for (var i = arr.length - 1; i >= 0 && arr[i][1] >= lo; --i) {
        var r = cb(arr[i]);
        if (r) {
          return r;
        }
      }
    }
    function reportRange(arr, cb) {
      for (var i = 0; i < arr.length; ++i) {
        var r = cb(arr[i]);
        if (r) {
          return r;
        }
      }
    }
    proto.queryPoint = function(x3, cb) {
      if (x3 < this.mid) {
        if (this.left) {
          var r = this.left.queryPoint(x3, cb);
          if (r) {
            return r;
          }
        }
        return reportLeftRange(this.leftPoints, x3, cb);
      } else if (x3 > this.mid) {
        if (this.right) {
          var r = this.right.queryPoint(x3, cb);
          if (r) {
            return r;
          }
        }
        return reportRightRange(this.rightPoints, x3, cb);
      } else {
        return reportRange(this.leftPoints, cb);
      }
    };
    proto.queryInterval = function(lo, hi, cb) {
      if (lo < this.mid && this.left) {
        var r = this.left.queryInterval(lo, hi, cb);
        if (r) {
          return r;
        }
      }
      if (hi > this.mid && this.right) {
        var r = this.right.queryInterval(lo, hi, cb);
        if (r) {
          return r;
        }
      }
      if (hi < this.mid) {
        return reportLeftRange(this.leftPoints, hi, cb);
      } else if (lo > this.mid) {
        return reportRightRange(this.rightPoints, lo, cb);
      } else {
        return reportRange(this.leftPoints, cb);
      }
    };
    function compareNumbers(a2, b) {
      return a2 - b;
    }
    function compareBegin(a2, b) {
      var d = a2[0] - b[0];
      if (d) {
        return d;
      }
      return a2[1] - b[1];
    }
    function compareEnd(a2, b) {
      var d = a2[1] - b[1];
      if (d) {
        return d;
      }
      return a2[0] - b[0];
    }
    function createIntervalTree(intervals) {
      if (intervals.length === 0) {
        return null;
      }
      var pts = [];
      for (var i = 0; i < intervals.length; ++i) {
        pts.push(intervals[i][0], intervals[i][1]);
      }
      pts.sort(compareNumbers);
      var mid2 = pts[pts.length >> 1];
      var leftIntervals = [];
      var rightIntervals = [];
      var centerIntervals = [];
      for (var i = 0; i < intervals.length; ++i) {
        var s2 = intervals[i];
        if (s2[1] < mid2) {
          leftIntervals.push(s2);
        } else if (mid2 < s2[0]) {
          rightIntervals.push(s2);
        } else {
          centerIntervals.push(s2);
        }
      }
      var leftPoints = centerIntervals;
      var rightPoints = centerIntervals.slice();
      leftPoints.sort(compareBegin);
      rightPoints.sort(compareEnd);
      return new IntervalTreeNode(
        mid2,
        createIntervalTree(leftIntervals),
        createIntervalTree(rightIntervals),
        leftPoints,
        rightPoints
      );
    }
    function IntervalTree2(root2) {
      this.root = root2;
    }
    var tproto = IntervalTree2.prototype;
    tproto.insert = function(interval2) {
      if (this.root) {
        this.root.insert(interval2);
      } else {
        this.root = new IntervalTreeNode(interval2[0], null, null, [interval2], [interval2]);
      }
    };
    tproto.remove = function(interval2) {
      if (this.root) {
        var r = this.root.remove(interval2);
        if (r === EMPTY) {
          this.root = null;
        }
        return r !== NOT_FOUND;
      }
      return false;
    };
    tproto.queryPoint = function(p, cb) {
      if (this.root) {
        return this.root.queryPoint(p, cb);
      }
    };
    tproto.queryInterval = function(lo, hi, cb) {
      if (lo <= hi && this.root) {
        return this.root.queryInterval(lo, hi, cb);
      }
    };
    Object.defineProperty(tproto, "count", {
      get: function() {
        if (this.root) {
          return this.root.count;
        }
        return 0;
      }
    });
    Object.defineProperty(tproto, "intervals", {
      get: function() {
        if (this.root) {
          return this.root.intervals([]);
        }
        return [];
      }
    });
    function createWrapper(intervals) {
      if (!intervals || intervals.length === 0) {
        return new IntervalTree2(null);
      }
      return new IntervalTree2(createIntervalTree(intervals));
    }
  }
});

// node_modules/d3-array/src/ascending.js
function ascending(a2, b) {
  return a2 == null || b == null ? NaN : a2 < b ? -1 : a2 > b ? 1 : a2 >= b ? 0 : NaN;
}

// node_modules/d3-array/src/descending.js
function descending(a2, b) {
  return a2 == null || b == null ? NaN : b < a2 ? -1 : b > a2 ? 1 : b >= a2 ? 0 : NaN;
}

// node_modules/d3-array/src/bisector.js
function bisector(f) {
  let compare1, compare2, delta;
  if (f.length !== 2) {
    compare1 = ascending;
    compare2 = (d, x3) => ascending(f(d), x3);
    delta = (d, x3) => f(d) - x3;
  } else {
    compare1 = f === ascending || f === descending ? f : zero;
    compare2 = f;
    delta = f;
  }
  function left2(a2, x3, lo = 0, hi = a2.length) {
    if (lo < hi) {
      if (compare1(x3, x3) !== 0) return hi;
      do {
        const mid2 = lo + hi >>> 1;
        if (compare2(a2[mid2], x3) < 0) lo = mid2 + 1;
        else hi = mid2;
      } while (lo < hi);
    }
    return lo;
  }
  function right2(a2, x3, lo = 0, hi = a2.length) {
    if (lo < hi) {
      if (compare1(x3, x3) !== 0) return hi;
      do {
        const mid2 = lo + hi >>> 1;
        if (compare2(a2[mid2], x3) <= 0) lo = mid2 + 1;
        else hi = mid2;
      } while (lo < hi);
    }
    return lo;
  }
  function center2(a2, x3, lo = 0, hi = a2.length) {
    const i = left2(a2, x3, lo, hi - 1);
    return i > lo && delta(a2[i - 1], x3) > -delta(a2[i], x3) ? i - 1 : i;
  }
  return { left: left2, center: center2, right: right2 };
}
function zero() {
  return 0;
}

// node_modules/d3-array/src/number.js
function number(x3) {
  return x3 === null ? NaN : +x3;
}
function* numbers(values2, valueof2) {
  if (valueof2 === void 0) {
    for (let value of values2) {
      if (value != null && (value = +value) >= value) {
        yield value;
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (value = +value) >= value) {
        yield value;
      }
    }
  }
}

// node_modules/d3-array/src/bisect.js
var ascendingBisect = bisector(ascending);
var bisectRight = ascendingBisect.right;
var bisectLeft = ascendingBisect.left;
var bisectCenter = bisector(number).center;
var bisect_default = bisectRight;

// node_modules/d3-array/src/blur.js
var blur2 = Blur2(blurf);
var blurImage = Blur2(blurfImage);
function Blur2(blur3) {
  return function(data, rx, ry = rx) {
    if (!((rx = +rx) >= 0)) throw new RangeError("invalid rx");
    if (!((ry = +ry) >= 0)) throw new RangeError("invalid ry");
    let { data: values2, width, height } = data;
    if (!((width = Math.floor(width)) >= 0)) throw new RangeError("invalid width");
    if (!((height = Math.floor(height !== void 0 ? height : values2.length / width)) >= 0)) throw new RangeError("invalid height");
    if (!width || !height || !rx && !ry) return data;
    const blurx = rx && blur3(rx);
    const blury = ry && blur3(ry);
    const temp = values2.slice();
    if (blurx && blury) {
      blurh(blurx, temp, values2, width, height);
      blurh(blurx, values2, temp, width, height);
      blurh(blurx, temp, values2, width, height);
      blurv(blury, values2, temp, width, height);
      blurv(blury, temp, values2, width, height);
      blurv(blury, values2, temp, width, height);
    } else if (blurx) {
      blurh(blurx, values2, temp, width, height);
      blurh(blurx, temp, values2, width, height);
      blurh(blurx, values2, temp, width, height);
    } else if (blury) {
      blurv(blury, values2, temp, width, height);
      blurv(blury, temp, values2, width, height);
      blurv(blury, values2, temp, width, height);
    }
    return data;
  };
}
function blurh(blur3, T, S, w, h) {
  for (let y3 = 0, n = w * h; y3 < n; ) {
    blur3(T, S, y3, y3 += w, 1);
  }
}
function blurv(blur3, T, S, w, h) {
  for (let x3 = 0, n = w * h; x3 < w; ++x3) {
    blur3(T, S, x3, x3 + n, w);
  }
}
function blurfImage(radius2) {
  const blur3 = blurf(radius2);
  return (T, S, start2, stop, step) => {
    start2 <<= 2, stop <<= 2, step <<= 2;
    blur3(T, S, start2 + 0, stop + 0, step);
    blur3(T, S, start2 + 1, stop + 1, step);
    blur3(T, S, start2 + 2, stop + 2, step);
    blur3(T, S, start2 + 3, stop + 3, step);
  };
}
function blurf(radius2) {
  const radius0 = Math.floor(radius2);
  if (radius0 === radius2) return bluri(radius2);
  const t = radius2 - radius0;
  const w = 2 * radius2 + 1;
  return (T, S, start2, stop, step) => {
    if (!((stop -= step) >= start2)) return;
    let sum4 = radius0 * S[start2];
    const s0 = step * radius0;
    const s1 = s0 + step;
    for (let i = start2, j = start2 + s0; i < j; i += step) {
      sum4 += S[Math.min(stop, i)];
    }
    for (let i = start2, j = stop; i <= j; i += step) {
      sum4 += S[Math.min(stop, i + s0)];
      T[i] = (sum4 + t * (S[Math.max(start2, i - s1)] + S[Math.min(stop, i + s1)])) / w;
      sum4 -= S[Math.max(start2, i - s0)];
    }
  };
}
function bluri(radius2) {
  const w = 2 * radius2 + 1;
  return (T, S, start2, stop, step) => {
    if (!((stop -= step) >= start2)) return;
    let sum4 = radius2 * S[start2];
    const s2 = step * radius2;
    for (let i = start2, j = start2 + s2; i < j; i += step) {
      sum4 += S[Math.min(stop, i)];
    }
    for (let i = start2, j = stop; i <= j; i += step) {
      sum4 += S[Math.min(stop, i + s2)];
      T[i] = sum4 / w;
      sum4 -= S[Math.max(start2, i - s2)];
    }
  };
}

// node_modules/d3-array/src/count.js
function count(values2, valueof2) {
  let count3 = 0;
  if (valueof2 === void 0) {
    for (let value of values2) {
      if (value != null && (value = +value) >= value) {
        ++count3;
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (value = +value) >= value) {
        ++count3;
      }
    }
  }
  return count3;
}

// node_modules/d3-array/src/cross.js
function length(array4) {
  return array4.length | 0;
}
function empty(length3) {
  return !(length3 > 0);
}
function arrayify(values2) {
  return typeof values2 !== "object" || "length" in values2 ? values2 : Array.from(values2);
}
function reducer(reduce2) {
  return (values2) => reduce2(...values2);
}
function cross(...values2) {
  const reduce2 = typeof values2[values2.length - 1] === "function" && reducer(values2.pop());
  values2 = values2.map(arrayify);
  const lengths = values2.map(length);
  const j = values2.length - 1;
  const index2 = new Array(j + 1).fill(0);
  const product = [];
  if (j < 0 || lengths.some(empty)) return product;
  while (true) {
    product.push(index2.map((j2, i2) => values2[i2][j2]));
    let i = j;
    while (++index2[i] === lengths[i]) {
      if (i === 0) return reduce2 ? product.map(reduce2) : product;
      index2[i--] = 0;
    }
  }
}

// node_modules/d3-array/src/cumsum.js
function cumsum(values2, valueof2) {
  var sum4 = 0, index2 = 0;
  return Float64Array.from(values2, valueof2 === void 0 ? (v2) => sum4 += +v2 || 0 : (v2) => sum4 += +valueof2(v2, index2++, values2) || 0);
}

// node_modules/d3-array/src/variance.js
function variance(values2, valueof2) {
  let count3 = 0;
  let delta;
  let mean2 = 0;
  let sum4 = 0;
  if (valueof2 === void 0) {
    for (let value of values2) {
      if (value != null && (value = +value) >= value) {
        delta = value - mean2;
        mean2 += delta / ++count3;
        sum4 += delta * (value - mean2);
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (value = +value) >= value) {
        delta = value - mean2;
        mean2 += delta / ++count3;
        sum4 += delta * (value - mean2);
      }
    }
  }
  if (count3 > 1) return sum4 / (count3 - 1);
}

// node_modules/d3-array/src/deviation.js
function deviation(values2, valueof2) {
  const v2 = variance(values2, valueof2);
  return v2 ? Math.sqrt(v2) : v2;
}

// node_modules/d3-array/src/extent.js
function extent(values2, valueof2) {
  let min4;
  let max5;
  if (valueof2 === void 0) {
    for (const value of values2) {
      if (value != null) {
        if (min4 === void 0) {
          if (value >= value) min4 = max5 = value;
        } else {
          if (min4 > value) min4 = value;
          if (max5 < value) max5 = value;
        }
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null) {
        if (min4 === void 0) {
          if (value >= value) min4 = max5 = value;
        } else {
          if (min4 > value) min4 = value;
          if (max5 < value) max5 = value;
        }
      }
    }
  }
  return [min4, max5];
}

// node_modules/d3-array/src/fsum.js
var Adder = class {
  constructor() {
    this._partials = new Float64Array(32);
    this._n = 0;
  }
  add(x3) {
    const p = this._partials;
    let i = 0;
    for (let j = 0; j < this._n && j < 32; j++) {
      const y3 = p[j], hi = x3 + y3, lo = Math.abs(x3) < Math.abs(y3) ? x3 - (hi - y3) : y3 - (hi - x3);
      if (lo) p[i++] = lo;
      x3 = hi;
    }
    p[i] = x3;
    this._n = i + 1;
    return this;
  }
  valueOf() {
    const p = this._partials;
    let n = this._n, x3, y3, lo, hi = 0;
    if (n > 0) {
      hi = p[--n];
      while (n > 0) {
        x3 = hi;
        y3 = p[--n];
        hi = x3 + y3;
        lo = y3 - (hi - x3);
        if (lo) break;
      }
      if (n > 0 && (lo < 0 && p[n - 1] < 0 || lo > 0 && p[n - 1] > 0)) {
        y3 = lo * 2;
        x3 = hi + y3;
        if (y3 == x3 - hi) hi = x3;
      }
    }
    return hi;
  }
};

// node_modules/internmap/src/index.js
var InternMap = class extends Map {
  constructor(entries, key = keyof) {
    super();
    Object.defineProperties(this, { _intern: { value: /* @__PURE__ */ new Map() }, _key: { value: key } });
    if (entries != null) for (const [key2, value] of entries) this.set(key2, value);
  }
  get(key) {
    return super.get(intern_get(this, key));
  }
  has(key) {
    return super.has(intern_get(this, key));
  }
  set(key, value) {
    return super.set(intern_set(this, key), value);
  }
  delete(key) {
    return super.delete(intern_delete(this, key));
  }
};
var InternSet = class extends Set {
  constructor(values2, key = keyof) {
    super();
    Object.defineProperties(this, { _intern: { value: /* @__PURE__ */ new Map() }, _key: { value: key } });
    if (values2 != null) for (const value of values2) this.add(value);
  }
  has(value) {
    return super.has(intern_get(this, value));
  }
  add(value) {
    return super.add(intern_set(this, value));
  }
  delete(value) {
    return super.delete(intern_delete(this, value));
  }
};
function intern_get({ _intern, _key }, value) {
  const key = _key(value);
  return _intern.has(key) ? _intern.get(key) : value;
}
function intern_set({ _intern, _key }, value) {
  const key = _key(value);
  if (_intern.has(key)) return _intern.get(key);
  _intern.set(key, value);
  return value;
}
function intern_delete({ _intern, _key }, value) {
  const key = _key(value);
  if (_intern.has(key)) {
    value = _intern.get(key);
    _intern.delete(key);
  }
  return value;
}
function keyof(value) {
  return value !== null && typeof value === "object" ? value.valueOf() : value;
}

// node_modules/d3-array/src/identity.js
function identity(x3) {
  return x3;
}

// node_modules/d3-array/src/group.js
function group(values2, ...keys) {
  return nest(values2, identity, identity, keys);
}
function rollup(values2, reduce2, ...keys) {
  return nest(values2, identity, reduce2, keys);
}
function rollups(values2, reduce2, ...keys) {
  return nest(values2, Array.from, reduce2, keys);
}
function nest(values2, map6, reduce2, keys) {
  return (function regroup(values3, i) {
    if (i >= keys.length) return reduce2(values3);
    const groups2 = new InternMap();
    const keyof3 = keys[i++];
    let index2 = -1;
    for (const value of values3) {
      const key = keyof3(value, ++index2, values3);
      const group3 = groups2.get(key);
      if (group3) group3.push(value);
      else groups2.set(key, [value]);
    }
    for (const [key, values4] of groups2) {
      groups2.set(key, regroup(values4, i));
    }
    return map6(groups2);
  })(values2, 0);
}

// node_modules/d3-array/src/permute.js
function permute(source, keys) {
  return Array.from(keys, (key) => source[key]);
}

// node_modules/d3-array/src/sort.js
function sort(values2, ...F) {
  if (typeof values2[Symbol.iterator] !== "function") throw new TypeError("values is not iterable");
  values2 = Array.from(values2);
  let [f] = F;
  if (f && f.length !== 2 || F.length > 1) {
    const index2 = Uint32Array.from(values2, (d, i) => i);
    if (F.length > 1) {
      F = F.map((f2) => values2.map(f2));
      index2.sort((i, j) => {
        for (const f2 of F) {
          const c4 = ascendingDefined(f2[i], f2[j]);
          if (c4) return c4;
        }
      });
    } else {
      f = values2.map(f);
      index2.sort((i, j) => ascendingDefined(f[i], f[j]));
    }
    return permute(values2, index2);
  }
  return values2.sort(compareDefined(f));
}
function compareDefined(compare = ascending) {
  if (compare === ascending) return ascendingDefined;
  if (typeof compare !== "function") throw new TypeError("compare is not a function");
  return (a2, b) => {
    const x3 = compare(a2, b);
    if (x3 || x3 === 0) return x3;
    return (compare(b, b) === 0) - (compare(a2, a2) === 0);
  };
}
function ascendingDefined(a2, b) {
  return (a2 == null || !(a2 >= a2)) - (b == null || !(b >= b)) || (a2 < b ? -1 : a2 > b ? 1 : 0);
}

// node_modules/d3-array/src/groupSort.js
function groupSort(values2, reduce2, key) {
  return (reduce2.length !== 2 ? sort(rollup(values2, reduce2, key), (([ak, av], [bk, bv]) => ascending(av, bv) || ascending(ak, bk))) : sort(group(values2, key), (([ak, av], [bk, bv]) => reduce2(av, bv) || ascending(ak, bk)))).map(([key2]) => key2);
}

// node_modules/d3-array/src/array.js
var array = Array.prototype;
var slice = array.slice;
var map = array.map;

// node_modules/d3-array/src/ticks.js
var e10 = Math.sqrt(50);
var e5 = Math.sqrt(10);
var e2 = Math.sqrt(2);
function tickSpec(start2, stop, count3) {
  const step = (stop - start2) / Math.max(0, count3), power = Math.floor(Math.log10(step)), error = step / Math.pow(10, power), factor = error >= e10 ? 10 : error >= e5 ? 5 : error >= e2 ? 2 : 1;
  let i1, i2, inc2;
  if (power < 0) {
    inc2 = Math.pow(10, -power) / factor;
    i1 = Math.round(start2 * inc2);
    i2 = Math.round(stop * inc2);
    if (i1 / inc2 < start2) ++i1;
    if (i2 / inc2 > stop) --i2;
    inc2 = -inc2;
  } else {
    inc2 = Math.pow(10, power) * factor;
    i1 = Math.round(start2 / inc2);
    i2 = Math.round(stop / inc2);
    if (i1 * inc2 < start2) ++i1;
    if (i2 * inc2 > stop) --i2;
  }
  if (i2 < i1 && 0.5 <= count3 && count3 < 2) return tickSpec(start2, stop, count3 * 2);
  return [i1, i2, inc2];
}
function ticks(start2, stop, count3) {
  stop = +stop, start2 = +start2, count3 = +count3;
  if (!(count3 > 0)) return [];
  if (start2 === stop) return [start2];
  const reverse3 = stop < start2, [i1, i2, inc2] = reverse3 ? tickSpec(stop, start2, count3) : tickSpec(start2, stop, count3);
  if (!(i2 >= i1)) return [];
  const n = i2 - i1 + 1, ticks2 = new Array(n);
  if (reverse3) {
    if (inc2 < 0) for (let i = 0; i < n; ++i) ticks2[i] = (i2 - i) / -inc2;
    else for (let i = 0; i < n; ++i) ticks2[i] = (i2 - i) * inc2;
  } else {
    if (inc2 < 0) for (let i = 0; i < n; ++i) ticks2[i] = (i1 + i) / -inc2;
    else for (let i = 0; i < n; ++i) ticks2[i] = (i1 + i) * inc2;
  }
  return ticks2;
}
function tickIncrement(start2, stop, count3) {
  stop = +stop, start2 = +start2, count3 = +count3;
  return tickSpec(start2, stop, count3)[2];
}
function tickStep(start2, stop, count3) {
  stop = +stop, start2 = +start2, count3 = +count3;
  const reverse3 = stop < start2, inc2 = reverse3 ? tickIncrement(stop, start2, count3) : tickIncrement(start2, stop, count3);
  return (reverse3 ? -1 : 1) * (inc2 < 0 ? 1 / -inc2 : inc2);
}

// node_modules/d3-array/src/nice.js
function nice(start2, stop, count3) {
  let prestep;
  while (true) {
    const step = tickIncrement(start2, stop, count3);
    if (step === prestep || step === 0 || !isFinite(step)) {
      return [start2, stop];
    } else if (step > 0) {
      start2 = Math.floor(start2 / step) * step;
      stop = Math.ceil(stop / step) * step;
    } else if (step < 0) {
      start2 = Math.ceil(start2 * step) / step;
      stop = Math.floor(stop * step) / step;
    }
    prestep = step;
  }
}

// node_modules/d3-array/src/threshold/sturges.js
function thresholdSturges(values2) {
  return Math.max(1, Math.ceil(Math.log(count(values2)) / Math.LN2) + 1);
}

// node_modules/d3-array/src/max.js
function max(values2, valueof2) {
  let max5;
  if (valueof2 === void 0) {
    for (const value of values2) {
      if (value != null && (max5 < value || max5 === void 0 && value >= value)) {
        max5 = value;
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (max5 < value || max5 === void 0 && value >= value)) {
        max5 = value;
      }
    }
  }
  return max5;
}

// node_modules/d3-array/src/maxIndex.js
function maxIndex(values2, valueof2) {
  let max5;
  let maxIndex2 = -1;
  let index2 = -1;
  if (valueof2 === void 0) {
    for (const value of values2) {
      ++index2;
      if (value != null && (max5 < value || max5 === void 0 && value >= value)) {
        max5 = value, maxIndex2 = index2;
      }
    }
  } else {
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (max5 < value || max5 === void 0 && value >= value)) {
        max5 = value, maxIndex2 = index2;
      }
    }
  }
  return maxIndex2;
}

// node_modules/d3-array/src/min.js
function min(values2, valueof2) {
  let min4;
  if (valueof2 === void 0) {
    for (const value of values2) {
      if (value != null && (min4 > value || min4 === void 0 && value >= value)) {
        min4 = value;
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (min4 > value || min4 === void 0 && value >= value)) {
        min4 = value;
      }
    }
  }
  return min4;
}

// node_modules/d3-array/src/minIndex.js
function minIndex(values2, valueof2) {
  let min4;
  let minIndex2 = -1;
  let index2 = -1;
  if (valueof2 === void 0) {
    for (const value of values2) {
      ++index2;
      if (value != null && (min4 > value || min4 === void 0 && value >= value)) {
        min4 = value, minIndex2 = index2;
      }
    }
  } else {
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (min4 > value || min4 === void 0 && value >= value)) {
        min4 = value, minIndex2 = index2;
      }
    }
  }
  return minIndex2;
}

// node_modules/d3-array/src/quickselect.js
function quickselect(array4, k2, left2 = 0, right2 = Infinity, compare) {
  k2 = Math.floor(k2);
  left2 = Math.floor(Math.max(0, left2));
  right2 = Math.floor(Math.min(array4.length - 1, right2));
  if (!(left2 <= k2 && k2 <= right2)) return array4;
  compare = compare === void 0 ? ascendingDefined : compareDefined(compare);
  while (right2 > left2) {
    if (right2 - left2 > 600) {
      const n = right2 - left2 + 1;
      const m = k2 - left2 + 1;
      const z = Math.log(n);
      const s2 = 0.5 * Math.exp(2 * z / 3);
      const sd = 0.5 * Math.sqrt(z * s2 * (n - s2) / n) * (m - n / 2 < 0 ? -1 : 1);
      const newLeft = Math.max(left2, Math.floor(k2 - m * s2 / n + sd));
      const newRight = Math.min(right2, Math.floor(k2 + (n - m) * s2 / n + sd));
      quickselect(array4, k2, newLeft, newRight, compare);
    }
    const t = array4[k2];
    let i = left2;
    let j = right2;
    swap(array4, left2, k2);
    if (compare(array4[right2], t) > 0) swap(array4, left2, right2);
    while (i < j) {
      swap(array4, i, j), ++i, --j;
      while (compare(array4[i], t) < 0) ++i;
      while (compare(array4[j], t) > 0) --j;
    }
    if (compare(array4[left2], t) === 0) swap(array4, left2, j);
    else ++j, swap(array4, j, right2);
    if (j <= k2) left2 = j + 1;
    if (k2 <= j) right2 = j - 1;
  }
  return array4;
}
function swap(array4, i, j) {
  const t = array4[i];
  array4[i] = array4[j];
  array4[j] = t;
}

// node_modules/d3-array/src/greatest.js
function greatest(values2, compare = ascending) {
  let max5;
  let defined2 = false;
  if (compare.length === 1) {
    let maxValue;
    for (const element of values2) {
      const value = compare(element);
      if (defined2 ? ascending(value, maxValue) > 0 : ascending(value, value) === 0) {
        max5 = element;
        maxValue = value;
        defined2 = true;
      }
    }
  } else {
    for (const value of values2) {
      if (defined2 ? compare(value, max5) > 0 : compare(value, value) === 0) {
        max5 = value;
        defined2 = true;
      }
    }
  }
  return max5;
}

// node_modules/d3-array/src/quantile.js
function quantile(values2, p, valueof2) {
  values2 = Float64Array.from(numbers(values2, valueof2));
  if (!(n = values2.length) || isNaN(p = +p)) return;
  if (p <= 0 || n < 2) return min(values2);
  if (p >= 1) return max(values2);
  var n, i = (n - 1) * p, i0 = Math.floor(i), value0 = max(quickselect(values2, i0).subarray(0, i0 + 1)), value1 = min(values2.subarray(i0 + 1));
  return value0 + (value1 - value0) * (i - i0);
}
function quantileSorted(values2, p, valueof2 = number) {
  if (!(n = values2.length) || isNaN(p = +p)) return;
  if (p <= 0 || n < 2) return +valueof2(values2[0], 0, values2);
  if (p >= 1) return +valueof2(values2[n - 1], n - 1, values2);
  var n, i = (n - 1) * p, i0 = Math.floor(i), value0 = +valueof2(values2[i0], i0, values2), value1 = +valueof2(values2[i0 + 1], i0 + 1, values2);
  return value0 + (value1 - value0) * (i - i0);
}

// node_modules/d3-array/src/threshold/freedmanDiaconis.js
function thresholdFreedmanDiaconis(values2, min4, max5) {
  const c4 = count(values2), d = quantile(values2, 0.75) - quantile(values2, 0.25);
  return c4 && d ? Math.ceil((max5 - min4) / (2 * d * Math.pow(c4, -1 / 3))) : 1;
}

// node_modules/d3-array/src/threshold/scott.js
function thresholdScott(values2, min4, max5) {
  const c4 = count(values2), d = deviation(values2);
  return c4 && d ? Math.ceil((max5 - min4) * Math.cbrt(c4) / (3.49 * d)) : 1;
}

// node_modules/d3-array/src/mean.js
function mean(values2, valueof2) {
  let count3 = 0;
  let sum4 = 0;
  if (valueof2 === void 0) {
    for (let value of values2) {
      if (value != null && (value = +value) >= value) {
        ++count3, sum4 += value;
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && (value = +value) >= value) {
        ++count3, sum4 += value;
      }
    }
  }
  if (count3) return sum4 / count3;
}

// node_modules/d3-array/src/median.js
function median(values2, valueof2) {
  return quantile(values2, 0.5, valueof2);
}

// node_modules/d3-array/src/merge.js
function* flatten(arrays) {
  for (const array4 of arrays) {
    yield* array4;
  }
}
function merge(arrays) {
  return Array.from(flatten(arrays));
}

// node_modules/d3-array/src/mode.js
function mode(values2, valueof2) {
  const counts = new InternMap();
  if (valueof2 === void 0) {
    for (let value of values2) {
      if (value != null && value >= value) {
        counts.set(value, (counts.get(value) || 0) + 1);
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if ((value = valueof2(value, ++index2, values2)) != null && value >= value) {
        counts.set(value, (counts.get(value) || 0) + 1);
      }
    }
  }
  let modeValue;
  let modeCount = 0;
  for (const [value, count3] of counts) {
    if (count3 > modeCount) {
      modeCount = count3;
      modeValue = value;
    }
  }
  return modeValue;
}

// node_modules/d3-array/src/pairs.js
function pairs(values2, pairof = pair) {
  const pairs2 = [];
  let previous;
  let first2 = false;
  for (const value of values2) {
    if (first2) pairs2.push(pairof(previous, value));
    previous = value;
    first2 = true;
  }
  return pairs2;
}
function pair(a2, b) {
  return [a2, b];
}

// node_modules/d3-array/src/range.js
function range(start2, stop, step) {
  start2 = +start2, stop = +stop, step = (n = arguments.length) < 2 ? (stop = start2, start2 = 0, 1) : n < 3 ? 1 : +step;
  var i = -1, n = Math.max(0, Math.ceil((stop - start2) / step)) | 0, range3 = new Array(n);
  while (++i < n) {
    range3[i] = start2 + i * step;
  }
  return range3;
}

// node_modules/d3-array/src/rank.js
function rank(values2, valueof2 = ascending) {
  if (typeof values2[Symbol.iterator] !== "function") throw new TypeError("values is not iterable");
  let V = Array.from(values2);
  const R = new Float64Array(V.length);
  if (valueof2.length !== 2) V = V.map(valueof2), valueof2 = ascending;
  const compareIndex = (i, j) => valueof2(V[i], V[j]);
  let k2, r;
  values2 = Uint32Array.from(V, (_, i) => i);
  values2.sort(valueof2 === ascending ? (i, j) => ascendingDefined(V[i], V[j]) : compareDefined(compareIndex));
  values2.forEach((j, i) => {
    const c4 = compareIndex(j, k2 === void 0 ? j : k2);
    if (c4 >= 0) {
      if (k2 === void 0 || c4 > 0) k2 = j, r = i;
      R[j] = r;
    } else {
      R[j] = NaN;
    }
  });
  return R;
}

// node_modules/d3-array/src/least.js
function least(values2, compare = ascending) {
  let min4;
  let defined2 = false;
  if (compare.length === 1) {
    let minValue;
    for (const element of values2) {
      const value = compare(element);
      if (defined2 ? ascending(value, minValue) < 0 : ascending(value, value) === 0) {
        min4 = element;
        minValue = value;
        defined2 = true;
      }
    }
  } else {
    for (const value of values2) {
      if (defined2 ? compare(value, min4) < 0 : compare(value, value) === 0) {
        min4 = value;
        defined2 = true;
      }
    }
  }
  return min4;
}

// node_modules/d3-array/src/shuffle.js
var shuffle_default = shuffler(Math.random);
function shuffler(random) {
  return function shuffle3(array4, i0 = 0, i1 = array4.length) {
    let m = i1 - (i0 = +i0);
    while (m) {
      const i = random() * m-- | 0, t = array4[m + i0];
      array4[m + i0] = array4[i + i0];
      array4[i + i0] = t;
    }
    return array4;
  };
}

// node_modules/d3-array/src/sum.js
function sum(values2, valueof2) {
  let sum4 = 0;
  if (valueof2 === void 0) {
    for (let value of values2) {
      if (value = +value) {
        sum4 += value;
      }
    }
  } else {
    let index2 = -1;
    for (let value of values2) {
      if (value = +valueof2(value, ++index2, values2)) {
        sum4 += value;
      }
    }
  }
  return sum4;
}

// node_modules/d3-array/src/reverse.js
function reverse(values2) {
  if (typeof values2[Symbol.iterator] !== "function") throw new TypeError("values is not iterable");
  return Array.from(values2).reverse();
}

// node_modules/d3-axis/src/identity.js
function identity_default(x3) {
  return x3;
}

// node_modules/d3-axis/src/axis.js
var top = 1;
var right = 2;
var bottom = 3;
var left = 4;
var epsilon = 1e-6;
function translateX(x3) {
  return "translate(" + x3 + ",0)";
}
function translateY(y3) {
  return "translate(0," + y3 + ")";
}
function number2(scale3) {
  return (d) => +scale3(d);
}
function center(scale3, offset2) {
  offset2 = Math.max(0, scale3.bandwidth() - offset2 * 2) / 2;
  if (scale3.round()) offset2 = Math.round(offset2);
  return (d) => +scale3(d) + offset2;
}
function entering() {
  return !this.__axis;
}
function axis(orient, scale3) {
  var tickArguments = [], tickValues = null, tickFormat2 = null, tickSizeInner = 6, tickSizeOuter = 6, tickPadding = 3, offset2 = typeof window !== "undefined" && window.devicePixelRatio > 1 ? 0 : 0.5, k2 = orient === top || orient === left ? -1 : 1, x3 = orient === left || orient === right ? "x" : "y", transform2 = orient === top || orient === bottom ? translateX : translateY;
  function axis2(context) {
    var values2 = tickValues == null ? scale3.ticks ? scale3.ticks.apply(scale3, tickArguments) : scale3.domain() : tickValues, format3 = tickFormat2 == null ? scale3.tickFormat ? scale3.tickFormat.apply(scale3, tickArguments) : identity_default : tickFormat2, spacing = Math.max(tickSizeInner, 0) + tickPadding, range3 = scale3.range(), range0 = +range3[0] + offset2, range1 = +range3[range3.length - 1] + offset2, position3 = (scale3.bandwidth ? center : number2)(scale3.copy(), offset2), selection2 = context.selection ? context.selection() : context, path2 = selection2.selectAll(".domain").data([null]), tick = selection2.selectAll(".tick").data(values2, scale3).order(), tickExit = tick.exit(), tickEnter = tick.enter().append("g").attr("class", "tick"), line2 = tick.select("line"), text2 = tick.select("text");
    path2 = path2.merge(path2.enter().insert("path", ".tick").attr("class", "domain").attr("stroke", "currentColor"));
    tick = tick.merge(tickEnter);
    line2 = line2.merge(tickEnter.append("line").attr("stroke", "currentColor").attr(x3 + "2", k2 * tickSizeInner));
    text2 = text2.merge(tickEnter.append("text").attr("fill", "currentColor").attr(x3, k2 * spacing).attr("dy", orient === top ? "0em" : orient === bottom ? "0.71em" : "0.32em"));
    if (context !== selection2) {
      path2 = path2.transition(context);
      tick = tick.transition(context);
      line2 = line2.transition(context);
      text2 = text2.transition(context);
      tickExit = tickExit.transition(context).attr("opacity", epsilon).attr("transform", function(d) {
        return isFinite(d = position3(d)) ? transform2(d + offset2) : this.getAttribute("transform");
      });
      tickEnter.attr("opacity", epsilon).attr("transform", function(d) {
        var p = this.parentNode.__axis;
        return transform2((p && isFinite(p = p(d)) ? p : position3(d)) + offset2);
      });
    }
    tickExit.remove();
    path2.attr("d", orient === left || orient === right ? tickSizeOuter ? "M" + k2 * tickSizeOuter + "," + range0 + "H" + offset2 + "V" + range1 + "H" + k2 * tickSizeOuter : "M" + offset2 + "," + range0 + "V" + range1 : tickSizeOuter ? "M" + range0 + "," + k2 * tickSizeOuter + "V" + offset2 + "H" + range1 + "V" + k2 * tickSizeOuter : "M" + range0 + "," + offset2 + "H" + range1);
    tick.attr("opacity", 1).attr("transform", function(d) {
      return transform2(position3(d) + offset2);
    });
    line2.attr(x3 + "2", k2 * tickSizeInner);
    text2.attr(x3, k2 * spacing).text(format3);
    selection2.filter(entering).attr("fill", "none").attr("font-size", 10).attr("font-family", "sans-serif").attr("text-anchor", orient === right ? "start" : orient === left ? "end" : "middle");
    selection2.each(function() {
      this.__axis = position3;
    });
  }
  axis2.scale = function(_) {
    return arguments.length ? (scale3 = _, axis2) : scale3;
  };
  axis2.ticks = function() {
    return tickArguments = Array.from(arguments), axis2;
  };
  axis2.tickArguments = function(_) {
    return arguments.length ? (tickArguments = _ == null ? [] : Array.from(_), axis2) : tickArguments.slice();
  };
  axis2.tickValues = function(_) {
    return arguments.length ? (tickValues = _ == null ? null : Array.from(_), axis2) : tickValues && tickValues.slice();
  };
  axis2.tickFormat = function(_) {
    return arguments.length ? (tickFormat2 = _, axis2) : tickFormat2;
  };
  axis2.tickSize = function(_) {
    return arguments.length ? (tickSizeInner = tickSizeOuter = +_, axis2) : tickSizeInner;
  };
  axis2.tickSizeInner = function(_) {
    return arguments.length ? (tickSizeInner = +_, axis2) : tickSizeInner;
  };
  axis2.tickSizeOuter = function(_) {
    return arguments.length ? (tickSizeOuter = +_, axis2) : tickSizeOuter;
  };
  axis2.tickPadding = function(_) {
    return arguments.length ? (tickPadding = +_, axis2) : tickPadding;
  };
  axis2.offset = function(_) {
    return arguments.length ? (offset2 = +_, axis2) : offset2;
  };
  return axis2;
}
function axisBottom(scale3) {
  return axis(bottom, scale3);
}

// node_modules/d3-dispatch/src/dispatch.js
var noop = { value: () => {
} };
function dispatch() {
  for (var i = 0, n = arguments.length, _ = {}, t; i < n; ++i) {
    if (!(t = arguments[i] + "") || t in _ || /[\s.]/.test(t)) throw new Error("illegal type: " + t);
    _[t] = [];
  }
  return new Dispatch(_);
}
function Dispatch(_) {
  this._ = _;
}
function parseTypenames(typenames, types) {
  return typenames.trim().split(/^|\s+/).map(function(t) {
    var name = "", i = t.indexOf(".");
    if (i >= 0) name = t.slice(i + 1), t = t.slice(0, i);
    if (t && !types.hasOwnProperty(t)) throw new Error("unknown type: " + t);
    return { type: t, name };
  });
}
Dispatch.prototype = dispatch.prototype = {
  constructor: Dispatch,
  on: function(typename, callback) {
    var _ = this._, T = parseTypenames(typename + "", _), t, i = -1, n = T.length;
    if (arguments.length < 2) {
      while (++i < n) if ((t = (typename = T[i]).type) && (t = get(_[t], typename.name))) return t;
      return;
    }
    if (callback != null && typeof callback !== "function") throw new Error("invalid callback: " + callback);
    while (++i < n) {
      if (t = (typename = T[i]).type) _[t] = set(_[t], typename.name, callback);
      else if (callback == null) for (t in _) _[t] = set(_[t], typename.name, null);
    }
    return this;
  },
  copy: function() {
    var copy3 = {}, _ = this._;
    for (var t in _) copy3[t] = _[t].slice();
    return new Dispatch(copy3);
  },
  call: function(type2, that) {
    if ((n = arguments.length - 2) > 0) for (var args = new Array(n), i = 0, n, t; i < n; ++i) args[i] = arguments[i + 2];
    if (!this._.hasOwnProperty(type2)) throw new Error("unknown type: " + type2);
    for (t = this._[type2], i = 0, n = t.length; i < n; ++i) t[i].value.apply(that, args);
  },
  apply: function(type2, that, args) {
    if (!this._.hasOwnProperty(type2)) throw new Error("unknown type: " + type2);
    for (var t = this._[type2], i = 0, n = t.length; i < n; ++i) t[i].value.apply(that, args);
  }
};
function get(type2, name) {
  for (var i = 0, n = type2.length, c4; i < n; ++i) {
    if ((c4 = type2[i]).name === name) {
      return c4.value;
    }
  }
}
function set(type2, name, callback) {
  for (var i = 0, n = type2.length; i < n; ++i) {
    if (type2[i].name === name) {
      type2[i] = noop, type2 = type2.slice(0, i).concat(type2.slice(i + 1));
      break;
    }
  }
  if (callback != null) type2.push({ name, value: callback });
  return type2;
}
var dispatch_default = dispatch;

// node_modules/d3-selection/src/namespaces.js
var xhtml = "http://www.w3.org/1999/xhtml";
var namespaces_default = {
  svg: "http://www.w3.org/2000/svg",
  xhtml,
  xlink: "http://www.w3.org/1999/xlink",
  xml: "http://www.w3.org/XML/1998/namespace",
  xmlns: "http://www.w3.org/2000/xmlns/"
};

// node_modules/d3-selection/src/namespace.js
function namespace_default(name) {
  var prefix = name += "", i = prefix.indexOf(":");
  if (i >= 0 && (prefix = name.slice(0, i)) !== "xmlns") name = name.slice(i + 1);
  return namespaces_default.hasOwnProperty(prefix) ? { space: namespaces_default[prefix], local: name } : name;
}

// node_modules/d3-selection/src/creator.js
function creatorInherit(name) {
  return function() {
    var document2 = this.ownerDocument, uri = this.namespaceURI;
    return uri === xhtml && document2.documentElement.namespaceURI === xhtml ? document2.createElement(name) : document2.createElementNS(uri, name);
  };
}
function creatorFixed(fullname) {
  return function() {
    return this.ownerDocument.createElementNS(fullname.space, fullname.local);
  };
}
function creator_default(name) {
  var fullname = namespace_default(name);
  return (fullname.local ? creatorFixed : creatorInherit)(fullname);
}

// node_modules/d3-selection/src/selector.js
function none() {
}
function selector_default(selector) {
  return selector == null ? none : function() {
    return this.querySelector(selector);
  };
}

// node_modules/d3-selection/src/selection/select.js
function select_default(select2) {
  if (typeof select2 !== "function") select2 = selector_default(select2);
  for (var groups2 = this._groups, m = groups2.length, subgroups = new Array(m), j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, subgroup = subgroups[j] = new Array(n), node, subnode, i = 0; i < n; ++i) {
      if ((node = group3[i]) && (subnode = select2.call(node, node.__data__, i, group3))) {
        if ("__data__" in node) subnode.__data__ = node.__data__;
        subgroup[i] = subnode;
      }
    }
  }
  return new Selection(subgroups, this._parents);
}

// node_modules/d3-selection/src/array.js
function array2(x3) {
  return x3 == null ? [] : Array.isArray(x3) ? x3 : Array.from(x3);
}

// node_modules/d3-selection/src/selectorAll.js
function empty2() {
  return [];
}
function selectorAll_default(selector) {
  return selector == null ? empty2 : function() {
    return this.querySelectorAll(selector);
  };
}

// node_modules/d3-selection/src/selection/selectAll.js
function arrayAll(select2) {
  return function() {
    return array2(select2.apply(this, arguments));
  };
}
function selectAll_default(select2) {
  if (typeof select2 === "function") select2 = arrayAll(select2);
  else select2 = selectorAll_default(select2);
  for (var groups2 = this._groups, m = groups2.length, subgroups = [], parents = [], j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, node, i = 0; i < n; ++i) {
      if (node = group3[i]) {
        subgroups.push(select2.call(node, node.__data__, i, group3));
        parents.push(node);
      }
    }
  }
  return new Selection(subgroups, parents);
}

// node_modules/d3-selection/src/matcher.js
function matcher_default(selector) {
  return function() {
    return this.matches(selector);
  };
}
function childMatcher(selector) {
  return function(node) {
    return node.matches(selector);
  };
}

// node_modules/d3-selection/src/selection/selectChild.js
var find = Array.prototype.find;
function childFind(match) {
  return function() {
    return find.call(this.children, match);
  };
}
function childFirst() {
  return this.firstElementChild;
}
function selectChild_default(match) {
  return this.select(match == null ? childFirst : childFind(typeof match === "function" ? match : childMatcher(match)));
}

// node_modules/d3-selection/src/selection/selectChildren.js
var filter2 = Array.prototype.filter;
function children() {
  return Array.from(this.children);
}
function childrenFilter(match) {
  return function() {
    return filter2.call(this.children, match);
  };
}
function selectChildren_default(match) {
  return this.selectAll(match == null ? children : childrenFilter(typeof match === "function" ? match : childMatcher(match)));
}

// node_modules/d3-selection/src/selection/filter.js
function filter_default(match) {
  if (typeof match !== "function") match = matcher_default(match);
  for (var groups2 = this._groups, m = groups2.length, subgroups = new Array(m), j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, subgroup = subgroups[j] = [], node, i = 0; i < n; ++i) {
      if ((node = group3[i]) && match.call(node, node.__data__, i, group3)) {
        subgroup.push(node);
      }
    }
  }
  return new Selection(subgroups, this._parents);
}

// node_modules/d3-selection/src/selection/sparse.js
function sparse_default(update) {
  return new Array(update.length);
}

// node_modules/d3-selection/src/selection/enter.js
function enter_default() {
  return new Selection(this._enter || this._groups.map(sparse_default), this._parents);
}
function EnterNode(parent, datum2) {
  this.ownerDocument = parent.ownerDocument;
  this.namespaceURI = parent.namespaceURI;
  this._next = null;
  this._parent = parent;
  this.__data__ = datum2;
}
EnterNode.prototype = {
  constructor: EnterNode,
  appendChild: function(child) {
    return this._parent.insertBefore(child, this._next);
  },
  insertBefore: function(child, next) {
    return this._parent.insertBefore(child, next);
  },
  querySelector: function(selector) {
    return this._parent.querySelector(selector);
  },
  querySelectorAll: function(selector) {
    return this._parent.querySelectorAll(selector);
  }
};

// node_modules/d3-selection/src/constant.js
function constant_default(x3) {
  return function() {
    return x3;
  };
}

// node_modules/d3-selection/src/selection/data.js
function bindIndex(parent, group3, enter, update, exit, data) {
  var i = 0, node, groupLength = group3.length, dataLength = data.length;
  for (; i < dataLength; ++i) {
    if (node = group3[i]) {
      node.__data__ = data[i];
      update[i] = node;
    } else {
      enter[i] = new EnterNode(parent, data[i]);
    }
  }
  for (; i < groupLength; ++i) {
    if (node = group3[i]) {
      exit[i] = node;
    }
  }
}
function bindKey(parent, group3, enter, update, exit, data, key) {
  var i, node, nodeByKeyValue = /* @__PURE__ */ new Map(), groupLength = group3.length, dataLength = data.length, keyValues = new Array(groupLength), keyValue;
  for (i = 0; i < groupLength; ++i) {
    if (node = group3[i]) {
      keyValues[i] = keyValue = key.call(node, node.__data__, i, group3) + "";
      if (nodeByKeyValue.has(keyValue)) {
        exit[i] = node;
      } else {
        nodeByKeyValue.set(keyValue, node);
      }
    }
  }
  for (i = 0; i < dataLength; ++i) {
    keyValue = key.call(parent, data[i], i, data) + "";
    if (node = nodeByKeyValue.get(keyValue)) {
      update[i] = node;
      node.__data__ = data[i];
      nodeByKeyValue.delete(keyValue);
    } else {
      enter[i] = new EnterNode(parent, data[i]);
    }
  }
  for (i = 0; i < groupLength; ++i) {
    if ((node = group3[i]) && nodeByKeyValue.get(keyValues[i]) === node) {
      exit[i] = node;
    }
  }
}
function datum(node) {
  return node.__data__;
}
function data_default(value, key) {
  if (!arguments.length) return Array.from(this, datum);
  var bind = key ? bindKey : bindIndex, parents = this._parents, groups2 = this._groups;
  if (typeof value !== "function") value = constant_default(value);
  for (var m = groups2.length, update = new Array(m), enter = new Array(m), exit = new Array(m), j = 0; j < m; ++j) {
    var parent = parents[j], group3 = groups2[j], groupLength = group3.length, data = arraylike(value.call(parent, parent && parent.__data__, j, parents)), dataLength = data.length, enterGroup = enter[j] = new Array(dataLength), updateGroup = update[j] = new Array(dataLength), exitGroup = exit[j] = new Array(groupLength);
    bind(parent, group3, enterGroup, updateGroup, exitGroup, data, key);
    for (var i0 = 0, i1 = 0, previous, next; i0 < dataLength; ++i0) {
      if (previous = enterGroup[i0]) {
        if (i0 >= i1) i1 = i0 + 1;
        while (!(next = updateGroup[i1]) && ++i1 < dataLength) ;
        previous._next = next || null;
      }
    }
  }
  update = new Selection(update, parents);
  update._enter = enter;
  update._exit = exit;
  return update;
}
function arraylike(data) {
  return typeof data === "object" && "length" in data ? data : Array.from(data);
}

// node_modules/d3-selection/src/selection/exit.js
function exit_default() {
  return new Selection(this._exit || this._groups.map(sparse_default), this._parents);
}

// node_modules/d3-selection/src/selection/join.js
function join_default(onenter, onupdate, onexit) {
  var enter = this.enter(), update = this, exit = this.exit();
  if (typeof onenter === "function") {
    enter = onenter(enter);
    if (enter) enter = enter.selection();
  } else {
    enter = enter.append(onenter + "");
  }
  if (onupdate != null) {
    update = onupdate(update);
    if (update) update = update.selection();
  }
  if (onexit == null) exit.remove();
  else onexit(exit);
  return enter && update ? enter.merge(update).order() : update;
}

// node_modules/d3-selection/src/selection/merge.js
function merge_default(context) {
  var selection2 = context.selection ? context.selection() : context;
  for (var groups0 = this._groups, groups1 = selection2._groups, m0 = groups0.length, m1 = groups1.length, m = Math.min(m0, m1), merges = new Array(m0), j = 0; j < m; ++j) {
    for (var group0 = groups0[j], group1 = groups1[j], n = group0.length, merge2 = merges[j] = new Array(n), node, i = 0; i < n; ++i) {
      if (node = group0[i] || group1[i]) {
        merge2[i] = node;
      }
    }
  }
  for (; j < m0; ++j) {
    merges[j] = groups0[j];
  }
  return new Selection(merges, this._parents);
}

// node_modules/d3-selection/src/selection/order.js
function order_default() {
  for (var groups2 = this._groups, j = -1, m = groups2.length; ++j < m; ) {
    for (var group3 = groups2[j], i = group3.length - 1, next = group3[i], node; --i >= 0; ) {
      if (node = group3[i]) {
        if (next && node.compareDocumentPosition(next) ^ 4) next.parentNode.insertBefore(node, next);
        next = node;
      }
    }
  }
  return this;
}

// node_modules/d3-selection/src/selection/sort.js
function sort_default(compare) {
  if (!compare) compare = ascending2;
  function compareNode(a2, b) {
    return a2 && b ? compare(a2.__data__, b.__data__) : !a2 - !b;
  }
  for (var groups2 = this._groups, m = groups2.length, sortgroups = new Array(m), j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, sortgroup = sortgroups[j] = new Array(n), node, i = 0; i < n; ++i) {
      if (node = group3[i]) {
        sortgroup[i] = node;
      }
    }
    sortgroup.sort(compareNode);
  }
  return new Selection(sortgroups, this._parents).order();
}
function ascending2(a2, b) {
  return a2 < b ? -1 : a2 > b ? 1 : a2 >= b ? 0 : NaN;
}

// node_modules/d3-selection/src/selection/call.js
function call_default() {
  var callback = arguments[0];
  arguments[0] = this;
  callback.apply(null, arguments);
  return this;
}

// node_modules/d3-selection/src/selection/nodes.js
function nodes_default() {
  return Array.from(this);
}

// node_modules/d3-selection/src/selection/node.js
function node_default() {
  for (var groups2 = this._groups, j = 0, m = groups2.length; j < m; ++j) {
    for (var group3 = groups2[j], i = 0, n = group3.length; i < n; ++i) {
      var node = group3[i];
      if (node) return node;
    }
  }
  return null;
}

// node_modules/d3-selection/src/selection/size.js
function size_default() {
  let size = 0;
  for (const node of this) ++size;
  return size;
}

// node_modules/d3-selection/src/selection/empty.js
function empty_default() {
  return !this.node();
}

// node_modules/d3-selection/src/selection/each.js
function each_default(callback) {
  for (var groups2 = this._groups, j = 0, m = groups2.length; j < m; ++j) {
    for (var group3 = groups2[j], i = 0, n = group3.length, node; i < n; ++i) {
      if (node = group3[i]) callback.call(node, node.__data__, i, group3);
    }
  }
  return this;
}

// node_modules/d3-selection/src/selection/attr.js
function attrRemove(name) {
  return function() {
    this.removeAttribute(name);
  };
}
function attrRemoveNS(fullname) {
  return function() {
    this.removeAttributeNS(fullname.space, fullname.local);
  };
}
function attrConstant(name, value) {
  return function() {
    this.setAttribute(name, value);
  };
}
function attrConstantNS(fullname, value) {
  return function() {
    this.setAttributeNS(fullname.space, fullname.local, value);
  };
}
function attrFunction(name, value) {
  return function() {
    var v2 = value.apply(this, arguments);
    if (v2 == null) this.removeAttribute(name);
    else this.setAttribute(name, v2);
  };
}
function attrFunctionNS(fullname, value) {
  return function() {
    var v2 = value.apply(this, arguments);
    if (v2 == null) this.removeAttributeNS(fullname.space, fullname.local);
    else this.setAttributeNS(fullname.space, fullname.local, v2);
  };
}
function attr_default(name, value) {
  var fullname = namespace_default(name);
  if (arguments.length < 2) {
    var node = this.node();
    return fullname.local ? node.getAttributeNS(fullname.space, fullname.local) : node.getAttribute(fullname);
  }
  return this.each((value == null ? fullname.local ? attrRemoveNS : attrRemove : typeof value === "function" ? fullname.local ? attrFunctionNS : attrFunction : fullname.local ? attrConstantNS : attrConstant)(fullname, value));
}

// node_modules/d3-selection/src/window.js
function window_default(node) {
  return node.ownerDocument && node.ownerDocument.defaultView || node.document && node || node.defaultView;
}

// node_modules/d3-selection/src/selection/style.js
function styleRemove(name) {
  return function() {
    this.style.removeProperty(name);
  };
}
function styleConstant(name, value, priority) {
  return function() {
    this.style.setProperty(name, value, priority);
  };
}
function styleFunction(name, value, priority) {
  return function() {
    var v2 = value.apply(this, arguments);
    if (v2 == null) this.style.removeProperty(name);
    else this.style.setProperty(name, v2, priority);
  };
}
function style_default(name, value, priority) {
  return arguments.length > 1 ? this.each((value == null ? styleRemove : typeof value === "function" ? styleFunction : styleConstant)(name, value, priority == null ? "" : priority)) : styleValue(this.node(), name);
}
function styleValue(node, name) {
  return node.style.getPropertyValue(name) || window_default(node).getComputedStyle(node, null).getPropertyValue(name);
}

// node_modules/d3-selection/src/selection/property.js
function propertyRemove(name) {
  return function() {
    delete this[name];
  };
}
function propertyConstant(name, value) {
  return function() {
    this[name] = value;
  };
}
function propertyFunction(name, value) {
  return function() {
    var v2 = value.apply(this, arguments);
    if (v2 == null) delete this[name];
    else this[name] = v2;
  };
}
function property_default(name, value) {
  return arguments.length > 1 ? this.each((value == null ? propertyRemove : typeof value === "function" ? propertyFunction : propertyConstant)(name, value)) : this.node()[name];
}

// node_modules/d3-selection/src/selection/classed.js
function classArray(string2) {
  return string2.trim().split(/^|\s+/);
}
function classList(node) {
  return node.classList || new ClassList(node);
}
function ClassList(node) {
  this._node = node;
  this._names = classArray(node.getAttribute("class") || "");
}
ClassList.prototype = {
  add: function(name) {
    var i = this._names.indexOf(name);
    if (i < 0) {
      this._names.push(name);
      this._node.setAttribute("class", this._names.join(" "));
    }
  },
  remove: function(name) {
    var i = this._names.indexOf(name);
    if (i >= 0) {
      this._names.splice(i, 1);
      this._node.setAttribute("class", this._names.join(" "));
    }
  },
  contains: function(name) {
    return this._names.indexOf(name) >= 0;
  }
};
function classedAdd(node, names) {
  var list = classList(node), i = -1, n = names.length;
  while (++i < n) list.add(names[i]);
}
function classedRemove(node, names) {
  var list = classList(node), i = -1, n = names.length;
  while (++i < n) list.remove(names[i]);
}
function classedTrue(names) {
  return function() {
    classedAdd(this, names);
  };
}
function classedFalse(names) {
  return function() {
    classedRemove(this, names);
  };
}
function classedFunction(names, value) {
  return function() {
    (value.apply(this, arguments) ? classedAdd : classedRemove)(this, names);
  };
}
function classed_default(name, value) {
  var names = classArray(name + "");
  if (arguments.length < 2) {
    var list = classList(this.node()), i = -1, n = names.length;
    while (++i < n) if (!list.contains(names[i])) return false;
    return true;
  }
  return this.each((typeof value === "function" ? classedFunction : value ? classedTrue : classedFalse)(names, value));
}

// node_modules/d3-selection/src/selection/text.js
function textRemove() {
  this.textContent = "";
}
function textConstant(value) {
  return function() {
    this.textContent = value;
  };
}
function textFunction(value) {
  return function() {
    var v2 = value.apply(this, arguments);
    this.textContent = v2 == null ? "" : v2;
  };
}
function text_default(value) {
  return arguments.length ? this.each(value == null ? textRemove : (typeof value === "function" ? textFunction : textConstant)(value)) : this.node().textContent;
}

// node_modules/d3-selection/src/selection/html.js
function htmlRemove() {
  this.innerHTML = "";
}
function htmlConstant(value) {
  return function() {
    this.innerHTML = value;
  };
}
function htmlFunction(value) {
  return function() {
    var v2 = value.apply(this, arguments);
    this.innerHTML = v2 == null ? "" : v2;
  };
}
function html_default(value) {
  return arguments.length ? this.each(value == null ? htmlRemove : (typeof value === "function" ? htmlFunction : htmlConstant)(value)) : this.node().innerHTML;
}

// node_modules/d3-selection/src/selection/raise.js
function raise() {
  if (this.nextSibling) this.parentNode.appendChild(this);
}
function raise_default() {
  return this.each(raise);
}

// node_modules/d3-selection/src/selection/lower.js
function lower() {
  if (this.previousSibling) this.parentNode.insertBefore(this, this.parentNode.firstChild);
}
function lower_default() {
  return this.each(lower);
}

// node_modules/d3-selection/src/selection/append.js
function append_default(name) {
  var create3 = typeof name === "function" ? name : creator_default(name);
  return this.select(function() {
    return this.appendChild(create3.apply(this, arguments));
  });
}

// node_modules/d3-selection/src/selection/insert.js
function constantNull() {
  return null;
}
function insert_default(name, before) {
  var create3 = typeof name === "function" ? name : creator_default(name), select2 = before == null ? constantNull : typeof before === "function" ? before : selector_default(before);
  return this.select(function() {
    return this.insertBefore(create3.apply(this, arguments), select2.apply(this, arguments) || null);
  });
}

// node_modules/d3-selection/src/selection/remove.js
function remove() {
  var parent = this.parentNode;
  if (parent) parent.removeChild(this);
}
function remove_default() {
  return this.each(remove);
}

// node_modules/d3-selection/src/selection/clone.js
function selection_cloneShallow() {
  var clone = this.cloneNode(false), parent = this.parentNode;
  return parent ? parent.insertBefore(clone, this.nextSibling) : clone;
}
function selection_cloneDeep() {
  var clone = this.cloneNode(true), parent = this.parentNode;
  return parent ? parent.insertBefore(clone, this.nextSibling) : clone;
}
function clone_default(deep) {
  return this.select(deep ? selection_cloneDeep : selection_cloneShallow);
}

// node_modules/d3-selection/src/selection/datum.js
function datum_default(value) {
  return arguments.length ? this.property("__data__", value) : this.node().__data__;
}

// node_modules/d3-selection/src/selection/on.js
function contextListener(listener) {
  return function(event) {
    listener.call(this, event, this.__data__);
  };
}
function parseTypenames2(typenames) {
  return typenames.trim().split(/^|\s+/).map(function(t) {
    var name = "", i = t.indexOf(".");
    if (i >= 0) name = t.slice(i + 1), t = t.slice(0, i);
    return { type: t, name };
  });
}
function onRemove(typename) {
  return function() {
    var on = this.__on;
    if (!on) return;
    for (var j = 0, i = -1, m = on.length, o; j < m; ++j) {
      if (o = on[j], (!typename.type || o.type === typename.type) && o.name === typename.name) {
        this.removeEventListener(o.type, o.listener, o.options);
      } else {
        on[++i] = o;
      }
    }
    if (++i) on.length = i;
    else delete this.__on;
  };
}
function onAdd(typename, value, options) {
  return function() {
    var on = this.__on, o, listener = contextListener(value);
    if (on) for (var j = 0, m = on.length; j < m; ++j) {
      if ((o = on[j]).type === typename.type && o.name === typename.name) {
        this.removeEventListener(o.type, o.listener, o.options);
        this.addEventListener(o.type, o.listener = listener, o.options = options);
        o.value = value;
        return;
      }
    }
    this.addEventListener(typename.type, listener, options);
    o = { type: typename.type, name: typename.name, value, listener, options };
    if (!on) this.__on = [o];
    else on.push(o);
  };
}
function on_default(typename, value, options) {
  var typenames = parseTypenames2(typename + ""), i, n = typenames.length, t;
  if (arguments.length < 2) {
    var on = this.node().__on;
    if (on) for (var j = 0, m = on.length, o; j < m; ++j) {
      for (i = 0, o = on[j]; i < n; ++i) {
        if ((t = typenames[i]).type === o.type && t.name === o.name) {
          return o.value;
        }
      }
    }
    return;
  }
  on = value ? onAdd : onRemove;
  for (i = 0; i < n; ++i) this.each(on(typenames[i], value, options));
  return this;
}

// node_modules/d3-selection/src/selection/dispatch.js
function dispatchEvent(node, type2, params) {
  var window3 = window_default(node), event = window3.CustomEvent;
  if (typeof event === "function") {
    event = new event(type2, params);
  } else {
    event = window3.document.createEvent("Event");
    if (params) event.initEvent(type2, params.bubbles, params.cancelable), event.detail = params.detail;
    else event.initEvent(type2, false, false);
  }
  node.dispatchEvent(event);
}
function dispatchConstant(type2, params) {
  return function() {
    return dispatchEvent(this, type2, params);
  };
}
function dispatchFunction(type2, params) {
  return function() {
    return dispatchEvent(this, type2, params.apply(this, arguments));
  };
}
function dispatch_default2(type2, params) {
  return this.each((typeof params === "function" ? dispatchFunction : dispatchConstant)(type2, params));
}

// node_modules/d3-selection/src/selection/iterator.js
function* iterator_default() {
  for (var groups2 = this._groups, j = 0, m = groups2.length; j < m; ++j) {
    for (var group3 = groups2[j], i = 0, n = group3.length, node; i < n; ++i) {
      if (node = group3[i]) yield node;
    }
  }
}

// node_modules/d3-selection/src/selection/index.js
var root = [null];
function Selection(groups2, parents) {
  this._groups = groups2;
  this._parents = parents;
}
function selection() {
  return new Selection([[document.documentElement]], root);
}
function selection_selection() {
  return this;
}
Selection.prototype = selection.prototype = {
  constructor: Selection,
  select: select_default,
  selectAll: selectAll_default,
  selectChild: selectChild_default,
  selectChildren: selectChildren_default,
  filter: filter_default,
  data: data_default,
  enter: enter_default,
  exit: exit_default,
  join: join_default,
  merge: merge_default,
  selection: selection_selection,
  order: order_default,
  sort: sort_default,
  call: call_default,
  nodes: nodes_default,
  node: node_default,
  size: size_default,
  empty: empty_default,
  each: each_default,
  attr: attr_default,
  style: style_default,
  property: property_default,
  classed: classed_default,
  text: text_default,
  html: html_default,
  raise: raise_default,
  lower: lower_default,
  append: append_default,
  insert: insert_default,
  remove: remove_default,
  clone: clone_default,
  datum: datum_default,
  on: on_default,
  dispatch: dispatch_default2,
  [Symbol.iterator]: iterator_default
};
var selection_default = selection;

// node_modules/d3-selection/src/select.js
function select_default2(selector) {
  return typeof selector === "string" ? new Selection([[document.querySelector(selector)]], [document.documentElement]) : new Selection([[selector]], root);
}

// node_modules/d3-selection/src/local.js
var nextId = 0;
function local() {
  return new Local();
}
function Local() {
  this._ = "@" + (++nextId).toString(36);
}
Local.prototype = local.prototype = {
  constructor: Local,
  get: function(node) {
    var id2 = this._;
    while (!(id2 in node)) if (!(node = node.parentNode)) return;
    return node[id2];
  },
  set: function(node, value) {
    return node[this._] = value;
  },
  remove: function(node) {
    return this._ in node && delete node[this._];
  },
  toString: function() {
    return this._;
  }
};

// node_modules/d3-selection/src/sourceEvent.js
function sourceEvent_default(event) {
  let sourceEvent;
  while (sourceEvent = event.sourceEvent) event = sourceEvent;
  return event;
}

// node_modules/d3-selection/src/pointer.js
function pointer_default(event, node) {
  event = sourceEvent_default(event);
  if (node === void 0) node = event.currentTarget;
  if (node) {
    var svg2 = node.ownerSVGElement || node;
    if (svg2.createSVGPoint) {
      var point6 = svg2.createSVGPoint();
      point6.x = event.clientX, point6.y = event.clientY;
      point6 = point6.matrixTransform(node.getScreenCTM().inverse());
      return [point6.x, point6.y];
    }
    if (node.getBoundingClientRect) {
      var rect2 = node.getBoundingClientRect();
      return [event.clientX - rect2.left - node.clientLeft, event.clientY - rect2.top - node.clientTop];
    }
  }
  return [event.pageX, event.pageY];
}

// node_modules/d3-drag/src/event.js
function DragEvent(type2, {
  sourceEvent,
  subject,
  target,
  identifier,
  active,
  x: x3,
  y: y3,
  dx,
  dy,
  dispatch: dispatch2
}) {
  Object.defineProperties(this, {
    type: { value: type2, enumerable: true, configurable: true },
    sourceEvent: { value: sourceEvent, enumerable: true, configurable: true },
    subject: { value: subject, enumerable: true, configurable: true },
    target: { value: target, enumerable: true, configurable: true },
    identifier: { value: identifier, enumerable: true, configurable: true },
    active: { value: active, enumerable: true, configurable: true },
    x: { value: x3, enumerable: true, configurable: true },
    y: { value: y3, enumerable: true, configurable: true },
    dx: { value: dx, enumerable: true, configurable: true },
    dy: { value: dy, enumerable: true, configurable: true },
    _: { value: dispatch2 }
  });
}
DragEvent.prototype.on = function() {
  var value = this._.on.apply(this._, arguments);
  return value === this._ ? this : value;
};

// node_modules/d3-color/src/define.js
function define_default(constructor, factory, prototype) {
  constructor.prototype = factory.prototype = prototype;
  prototype.constructor = constructor;
}
function extend(parent, definition) {
  var prototype = Object.create(parent.prototype);
  for (var key in definition) prototype[key] = definition[key];
  return prototype;
}

// node_modules/d3-color/src/color.js
function Color() {
}
var darker = 0.7;
var brighter = 1 / darker;
var reI = "\\s*([+-]?\\d+)\\s*";
var reN = "\\s*([+-]?(?:\\d*\\.)?\\d+(?:[eE][+-]?\\d+)?)\\s*";
var reP = "\\s*([+-]?(?:\\d*\\.)?\\d+(?:[eE][+-]?\\d+)?)%\\s*";
var reHex = /^#([0-9a-f]{3,8})$/;
var reRgbInteger = new RegExp(`^rgb\\(${reI},${reI},${reI}\\)$`);
var reRgbPercent = new RegExp(`^rgb\\(${reP},${reP},${reP}\\)$`);
var reRgbaInteger = new RegExp(`^rgba\\(${reI},${reI},${reI},${reN}\\)$`);
var reRgbaPercent = new RegExp(`^rgba\\(${reP},${reP},${reP},${reN}\\)$`);
var reHslPercent = new RegExp(`^hsl\\(${reN},${reP},${reP}\\)$`);
var reHslaPercent = new RegExp(`^hsla\\(${reN},${reP},${reP},${reN}\\)$`);
var named = {
  aliceblue: 15792383,
  antiquewhite: 16444375,
  aqua: 65535,
  aquamarine: 8388564,
  azure: 15794175,
  beige: 16119260,
  bisque: 16770244,
  black: 0,
  blanchedalmond: 16772045,
  blue: 255,
  blueviolet: 9055202,
  brown: 10824234,
  burlywood: 14596231,
  cadetblue: 6266528,
  chartreuse: 8388352,
  chocolate: 13789470,
  coral: 16744272,
  cornflowerblue: 6591981,
  cornsilk: 16775388,
  crimson: 14423100,
  cyan: 65535,
  darkblue: 139,
  darkcyan: 35723,
  darkgoldenrod: 12092939,
  darkgray: 11119017,
  darkgreen: 25600,
  darkgrey: 11119017,
  darkkhaki: 12433259,
  darkmagenta: 9109643,
  darkolivegreen: 5597999,
  darkorange: 16747520,
  darkorchid: 10040012,
  darkred: 9109504,
  darksalmon: 15308410,
  darkseagreen: 9419919,
  darkslateblue: 4734347,
  darkslategray: 3100495,
  darkslategrey: 3100495,
  darkturquoise: 52945,
  darkviolet: 9699539,
  deeppink: 16716947,
  deepskyblue: 49151,
  dimgray: 6908265,
  dimgrey: 6908265,
  dodgerblue: 2003199,
  firebrick: 11674146,
  floralwhite: 16775920,
  forestgreen: 2263842,
  fuchsia: 16711935,
  gainsboro: 14474460,
  ghostwhite: 16316671,
  gold: 16766720,
  goldenrod: 14329120,
  gray: 8421504,
  green: 32768,
  greenyellow: 11403055,
  grey: 8421504,
  honeydew: 15794160,
  hotpink: 16738740,
  indianred: 13458524,
  indigo: 4915330,
  ivory: 16777200,
  khaki: 15787660,
  lavender: 15132410,
  lavenderblush: 16773365,
  lawngreen: 8190976,
  lemonchiffon: 16775885,
  lightblue: 11393254,
  lightcoral: 15761536,
  lightcyan: 14745599,
  lightgoldenrodyellow: 16448210,
  lightgray: 13882323,
  lightgreen: 9498256,
  lightgrey: 13882323,
  lightpink: 16758465,
  lightsalmon: 16752762,
  lightseagreen: 2142890,
  lightskyblue: 8900346,
  lightslategray: 7833753,
  lightslategrey: 7833753,
  lightsteelblue: 11584734,
  lightyellow: 16777184,
  lime: 65280,
  limegreen: 3329330,
  linen: 16445670,
  magenta: 16711935,
  maroon: 8388608,
  mediumaquamarine: 6737322,
  mediumblue: 205,
  mediumorchid: 12211667,
  mediumpurple: 9662683,
  mediumseagreen: 3978097,
  mediumslateblue: 8087790,
  mediumspringgreen: 64154,
  mediumturquoise: 4772300,
  mediumvioletred: 13047173,
  midnightblue: 1644912,
  mintcream: 16121850,
  mistyrose: 16770273,
  moccasin: 16770229,
  navajowhite: 16768685,
  navy: 128,
  oldlace: 16643558,
  olive: 8421376,
  olivedrab: 7048739,
  orange: 16753920,
  orangered: 16729344,
  orchid: 14315734,
  palegoldenrod: 15657130,
  palegreen: 10025880,
  paleturquoise: 11529966,
  palevioletred: 14381203,
  papayawhip: 16773077,
  peachpuff: 16767673,
  peru: 13468991,
  pink: 16761035,
  plum: 14524637,
  powderblue: 11591910,
  purple: 8388736,
  rebeccapurple: 6697881,
  red: 16711680,
  rosybrown: 12357519,
  royalblue: 4286945,
  saddlebrown: 9127187,
  salmon: 16416882,
  sandybrown: 16032864,
  seagreen: 3050327,
  seashell: 16774638,
  sienna: 10506797,
  silver: 12632256,
  skyblue: 8900331,
  slateblue: 6970061,
  slategray: 7372944,
  slategrey: 7372944,
  snow: 16775930,
  springgreen: 65407,
  steelblue: 4620980,
  tan: 13808780,
  teal: 32896,
  thistle: 14204888,
  tomato: 16737095,
  turquoise: 4251856,
  violet: 15631086,
  wheat: 16113331,
  white: 16777215,
  whitesmoke: 16119285,
  yellow: 16776960,
  yellowgreen: 10145074
};
define_default(Color, color, {
  copy(channels) {
    return Object.assign(new this.constructor(), this, channels);
  },
  displayable() {
    return this.rgb().displayable();
  },
  hex: color_formatHex,
  // Deprecated! Use color.formatHex.
  formatHex: color_formatHex,
  formatHex8: color_formatHex8,
  formatHsl: color_formatHsl,
  formatRgb: color_formatRgb,
  toString: color_formatRgb
});
function color_formatHex() {
  return this.rgb().formatHex();
}
function color_formatHex8() {
  return this.rgb().formatHex8();
}
function color_formatHsl() {
  return hslConvert(this).formatHsl();
}
function color_formatRgb() {
  return this.rgb().formatRgb();
}
function color(format3) {
  var m, l;
  format3 = (format3 + "").trim().toLowerCase();
  return (m = reHex.exec(format3)) ? (l = m[1].length, m = parseInt(m[1], 16), l === 6 ? rgbn(m) : l === 3 ? new Rgb(m >> 8 & 15 | m >> 4 & 240, m >> 4 & 15 | m & 240, (m & 15) << 4 | m & 15, 1) : l === 8 ? rgba(m >> 24 & 255, m >> 16 & 255, m >> 8 & 255, (m & 255) / 255) : l === 4 ? rgba(m >> 12 & 15 | m >> 8 & 240, m >> 8 & 15 | m >> 4 & 240, m >> 4 & 15 | m & 240, ((m & 15) << 4 | m & 15) / 255) : null) : (m = reRgbInteger.exec(format3)) ? new Rgb(m[1], m[2], m[3], 1) : (m = reRgbPercent.exec(format3)) ? new Rgb(m[1] * 255 / 100, m[2] * 255 / 100, m[3] * 255 / 100, 1) : (m = reRgbaInteger.exec(format3)) ? rgba(m[1], m[2], m[3], m[4]) : (m = reRgbaPercent.exec(format3)) ? rgba(m[1] * 255 / 100, m[2] * 255 / 100, m[3] * 255 / 100, m[4]) : (m = reHslPercent.exec(format3)) ? hsla(m[1], m[2] / 100, m[3] / 100, 1) : (m = reHslaPercent.exec(format3)) ? hsla(m[1], m[2] / 100, m[3] / 100, m[4]) : named.hasOwnProperty(format3) ? rgbn(named[format3]) : format3 === "transparent" ? new Rgb(NaN, NaN, NaN, 0) : null;
}
function rgbn(n) {
  return new Rgb(n >> 16 & 255, n >> 8 & 255, n & 255, 1);
}
function rgba(r, g, b, a2) {
  if (a2 <= 0) r = g = b = NaN;
  return new Rgb(r, g, b, a2);
}
function rgbConvert(o) {
  if (!(o instanceof Color)) o = color(o);
  if (!o) return new Rgb();
  o = o.rgb();
  return new Rgb(o.r, o.g, o.b, o.opacity);
}
function rgb(r, g, b, opacity2) {
  return arguments.length === 1 ? rgbConvert(r) : new Rgb(r, g, b, opacity2 == null ? 1 : opacity2);
}
function Rgb(r, g, b, opacity2) {
  this.r = +r;
  this.g = +g;
  this.b = +b;
  this.opacity = +opacity2;
}
define_default(Rgb, rgb, extend(Color, {
  brighter(k2) {
    k2 = k2 == null ? brighter : Math.pow(brighter, k2);
    return new Rgb(this.r * k2, this.g * k2, this.b * k2, this.opacity);
  },
  darker(k2) {
    k2 = k2 == null ? darker : Math.pow(darker, k2);
    return new Rgb(this.r * k2, this.g * k2, this.b * k2, this.opacity);
  },
  rgb() {
    return this;
  },
  clamp() {
    return new Rgb(clampi(this.r), clampi(this.g), clampi(this.b), clampa(this.opacity));
  },
  displayable() {
    return -0.5 <= this.r && this.r < 255.5 && (-0.5 <= this.g && this.g < 255.5) && (-0.5 <= this.b && this.b < 255.5) && (0 <= this.opacity && this.opacity <= 1);
  },
  hex: rgb_formatHex,
  // Deprecated! Use color.formatHex.
  formatHex: rgb_formatHex,
  formatHex8: rgb_formatHex8,
  formatRgb: rgb_formatRgb,
  toString: rgb_formatRgb
}));
function rgb_formatHex() {
  return `#${hex(this.r)}${hex(this.g)}${hex(this.b)}`;
}
function rgb_formatHex8() {
  return `#${hex(this.r)}${hex(this.g)}${hex(this.b)}${hex((isNaN(this.opacity) ? 1 : this.opacity) * 255)}`;
}
function rgb_formatRgb() {
  const a2 = clampa(this.opacity);
  return `${a2 === 1 ? "rgb(" : "rgba("}${clampi(this.r)}, ${clampi(this.g)}, ${clampi(this.b)}${a2 === 1 ? ")" : `, ${a2})`}`;
}
function clampa(opacity2) {
  return isNaN(opacity2) ? 1 : Math.max(0, Math.min(1, opacity2));
}
function clampi(value) {
  return Math.max(0, Math.min(255, Math.round(value) || 0));
}
function hex(value) {
  value = clampi(value);
  return (value < 16 ? "0" : "") + value.toString(16);
}
function hsla(h, s2, l, a2) {
  if (a2 <= 0) h = s2 = l = NaN;
  else if (l <= 0 || l >= 1) h = s2 = NaN;
  else if (s2 <= 0) h = NaN;
  return new Hsl(h, s2, l, a2);
}
function hslConvert(o) {
  if (o instanceof Hsl) return new Hsl(o.h, o.s, o.l, o.opacity);
  if (!(o instanceof Color)) o = color(o);
  if (!o) return new Hsl();
  if (o instanceof Hsl) return o;
  o = o.rgb();
  var r = o.r / 255, g = o.g / 255, b = o.b / 255, min4 = Math.min(r, g, b), max5 = Math.max(r, g, b), h = NaN, s2 = max5 - min4, l = (max5 + min4) / 2;
  if (s2) {
    if (r === max5) h = (g - b) / s2 + (g < b) * 6;
    else if (g === max5) h = (b - r) / s2 + 2;
    else h = (r - g) / s2 + 4;
    s2 /= l < 0.5 ? max5 + min4 : 2 - max5 - min4;
    h *= 60;
  } else {
    s2 = l > 0 && l < 1 ? 0 : h;
  }
  return new Hsl(h, s2, l, o.opacity);
}
function hsl(h, s2, l, opacity2) {
  return arguments.length === 1 ? hslConvert(h) : new Hsl(h, s2, l, opacity2 == null ? 1 : opacity2);
}
function Hsl(h, s2, l, opacity2) {
  this.h = +h;
  this.s = +s2;
  this.l = +l;
  this.opacity = +opacity2;
}
define_default(Hsl, hsl, extend(Color, {
  brighter(k2) {
    k2 = k2 == null ? brighter : Math.pow(brighter, k2);
    return new Hsl(this.h, this.s, this.l * k2, this.opacity);
  },
  darker(k2) {
    k2 = k2 == null ? darker : Math.pow(darker, k2);
    return new Hsl(this.h, this.s, this.l * k2, this.opacity);
  },
  rgb() {
    var h = this.h % 360 + (this.h < 0) * 360, s2 = isNaN(h) || isNaN(this.s) ? 0 : this.s, l = this.l, m2 = l + (l < 0.5 ? l : 1 - l) * s2, m1 = 2 * l - m2;
    return new Rgb(
      hsl2rgb(h >= 240 ? h - 240 : h + 120, m1, m2),
      hsl2rgb(h, m1, m2),
      hsl2rgb(h < 120 ? h + 240 : h - 120, m1, m2),
      this.opacity
    );
  },
  clamp() {
    return new Hsl(clamph(this.h), clampt(this.s), clampt(this.l), clampa(this.opacity));
  },
  displayable() {
    return (0 <= this.s && this.s <= 1 || isNaN(this.s)) && (0 <= this.l && this.l <= 1) && (0 <= this.opacity && this.opacity <= 1);
  },
  formatHsl() {
    const a2 = clampa(this.opacity);
    return `${a2 === 1 ? "hsl(" : "hsla("}${clamph(this.h)}, ${clampt(this.s) * 100}%, ${clampt(this.l) * 100}%${a2 === 1 ? ")" : `, ${a2})`}`;
  }
}));
function clamph(value) {
  value = (value || 0) % 360;
  return value < 0 ? value + 360 : value;
}
function clampt(value) {
  return Math.max(0, Math.min(1, value || 0));
}
function hsl2rgb(h, m1, m2) {
  return (h < 60 ? m1 + (m2 - m1) * h / 60 : h < 180 ? m2 : h < 240 ? m1 + (m2 - m1) * (240 - h) / 60 : m1) * 255;
}

// node_modules/d3-color/src/math.js
var radians = Math.PI / 180;
var degrees = 180 / Math.PI;

// node_modules/d3-color/src/lab.js
var K = 18;
var Xn = 0.96422;
var Yn = 1;
var Zn = 0.82521;
var t0 = 4 / 29;
var t1 = 6 / 29;
var t2 = 3 * t1 * t1;
var t3 = t1 * t1 * t1;
function labConvert(o) {
  if (o instanceof Lab) return new Lab(o.l, o.a, o.b, o.opacity);
  if (o instanceof Hcl) return hcl2lab(o);
  if (!(o instanceof Rgb)) o = rgbConvert(o);
  var r = rgb2lrgb(o.r), g = rgb2lrgb(o.g), b = rgb2lrgb(o.b), y3 = xyz2lab((0.2225045 * r + 0.7168786 * g + 0.0606169 * b) / Yn), x3, z;
  if (r === g && g === b) x3 = z = y3;
  else {
    x3 = xyz2lab((0.4360747 * r + 0.3850649 * g + 0.1430804 * b) / Xn);
    z = xyz2lab((0.0139322 * r + 0.0971045 * g + 0.7141733 * b) / Zn);
  }
  return new Lab(116 * y3 - 16, 500 * (x3 - y3), 200 * (y3 - z), o.opacity);
}
function lab(l, a2, b, opacity2) {
  return arguments.length === 1 ? labConvert(l) : new Lab(l, a2, b, opacity2 == null ? 1 : opacity2);
}
function Lab(l, a2, b, opacity2) {
  this.l = +l;
  this.a = +a2;
  this.b = +b;
  this.opacity = +opacity2;
}
define_default(Lab, lab, extend(Color, {
  brighter(k2) {
    return new Lab(this.l + K * (k2 == null ? 1 : k2), this.a, this.b, this.opacity);
  },
  darker(k2) {
    return new Lab(this.l - K * (k2 == null ? 1 : k2), this.a, this.b, this.opacity);
  },
  rgb() {
    var y3 = (this.l + 16) / 116, x3 = isNaN(this.a) ? y3 : y3 + this.a / 500, z = isNaN(this.b) ? y3 : y3 - this.b / 200;
    x3 = Xn * lab2xyz(x3);
    y3 = Yn * lab2xyz(y3);
    z = Zn * lab2xyz(z);
    return new Rgb(
      lrgb2rgb(3.1338561 * x3 - 1.6168667 * y3 - 0.4906146 * z),
      lrgb2rgb(-0.9787684 * x3 + 1.9161415 * y3 + 0.033454 * z),
      lrgb2rgb(0.0719453 * x3 - 0.2289914 * y3 + 1.4052427 * z),
      this.opacity
    );
  }
}));
function xyz2lab(t) {
  return t > t3 ? Math.pow(t, 1 / 3) : t / t2 + t0;
}
function lab2xyz(t) {
  return t > t1 ? t * t * t : t2 * (t - t0);
}
function lrgb2rgb(x3) {
  return 255 * (x3 <= 31308e-7 ? 12.92 * x3 : 1.055 * Math.pow(x3, 1 / 2.4) - 0.055);
}
function rgb2lrgb(x3) {
  return (x3 /= 255) <= 0.04045 ? x3 / 12.92 : Math.pow((x3 + 0.055) / 1.055, 2.4);
}
function hclConvert(o) {
  if (o instanceof Hcl) return new Hcl(o.h, o.c, o.l, o.opacity);
  if (!(o instanceof Lab)) o = labConvert(o);
  if (o.a === 0 && o.b === 0) return new Hcl(NaN, 0 < o.l && o.l < 100 ? 0 : NaN, o.l, o.opacity);
  var h = Math.atan2(o.b, o.a) * degrees;
  return new Hcl(h < 0 ? h + 360 : h, Math.sqrt(o.a * o.a + o.b * o.b), o.l, o.opacity);
}
function hcl(h, c4, l, opacity2) {
  return arguments.length === 1 ? hclConvert(h) : new Hcl(h, c4, l, opacity2 == null ? 1 : opacity2);
}
function Hcl(h, c4, l, opacity2) {
  this.h = +h;
  this.c = +c4;
  this.l = +l;
  this.opacity = +opacity2;
}
function hcl2lab(o) {
  if (isNaN(o.h)) return new Lab(o.l, 0, 0, o.opacity);
  var h = o.h * radians;
  return new Lab(o.l, Math.cos(h) * o.c, Math.sin(h) * o.c, o.opacity);
}
define_default(Hcl, hcl, extend(Color, {
  brighter(k2) {
    return new Hcl(this.h, this.c, this.l + K * (k2 == null ? 1 : k2), this.opacity);
  },
  darker(k2) {
    return new Hcl(this.h, this.c, this.l - K * (k2 == null ? 1 : k2), this.opacity);
  },
  rgb() {
    return hcl2lab(this).rgb();
  }
}));

// node_modules/d3-color/src/cubehelix.js
var A = -0.14861;
var B = 1.78277;
var C = -0.29227;
var D = -0.90649;
var E = 1.97294;
var ED = E * D;
var EB = E * B;
var BC_DA = B * C - D * A;
function cubehelixConvert(o) {
  if (o instanceof Cubehelix) return new Cubehelix(o.h, o.s, o.l, o.opacity);
  if (!(o instanceof Rgb)) o = rgbConvert(o);
  var r = o.r / 255, g = o.g / 255, b = o.b / 255, l = (BC_DA * b + ED * r - EB * g) / (BC_DA + ED - EB), bl = b - l, k2 = (E * (g - l) - C * bl) / D, s2 = Math.sqrt(k2 * k2 + bl * bl) / (E * l * (1 - l)), h = s2 ? Math.atan2(k2, bl) * degrees - 120 : NaN;
  return new Cubehelix(h < 0 ? h + 360 : h, s2, l, o.opacity);
}
function cubehelix(h, s2, l, opacity2) {
  return arguments.length === 1 ? cubehelixConvert(h) : new Cubehelix(h, s2, l, opacity2 == null ? 1 : opacity2);
}
function Cubehelix(h, s2, l, opacity2) {
  this.h = +h;
  this.s = +s2;
  this.l = +l;
  this.opacity = +opacity2;
}
define_default(Cubehelix, cubehelix, extend(Color, {
  brighter(k2) {
    k2 = k2 == null ? brighter : Math.pow(brighter, k2);
    return new Cubehelix(this.h, this.s, this.l * k2, this.opacity);
  },
  darker(k2) {
    k2 = k2 == null ? darker : Math.pow(darker, k2);
    return new Cubehelix(this.h, this.s, this.l * k2, this.opacity);
  },
  rgb() {
    var h = isNaN(this.h) ? 0 : (this.h + 120) * radians, l = +this.l, a2 = isNaN(this.s) ? 0 : this.s * l * (1 - l), cosh2 = Math.cos(h), sinh2 = Math.sin(h);
    return new Rgb(
      255 * (l + a2 * (A * cosh2 + B * sinh2)),
      255 * (l + a2 * (C * cosh2 + D * sinh2)),
      255 * (l + a2 * (E * cosh2)),
      this.opacity
    );
  }
}));

// node_modules/d3-interpolate/src/basis.js
function basis(t13, v0, v1, v2, v3) {
  var t22 = t13 * t13, t32 = t22 * t13;
  return ((1 - 3 * t13 + 3 * t22 - t32) * v0 + (4 - 6 * t22 + 3 * t32) * v1 + (1 + 3 * t13 + 3 * t22 - 3 * t32) * v2 + t32 * v3) / 6;
}
function basis_default(values2) {
  var n = values2.length - 1;
  return function(t) {
    var i = t <= 0 ? t = 0 : t >= 1 ? (t = 1, n - 1) : Math.floor(t * n), v1 = values2[i], v2 = values2[i + 1], v0 = i > 0 ? values2[i - 1] : 2 * v1 - v2, v3 = i < n - 1 ? values2[i + 2] : 2 * v2 - v1;
    return basis((t - i / n) * n, v0, v1, v2, v3);
  };
}

// node_modules/d3-interpolate/src/basisClosed.js
function basisClosed_default(values2) {
  var n = values2.length;
  return function(t) {
    var i = Math.floor(((t %= 1) < 0 ? ++t : t) * n), v0 = values2[(i + n - 1) % n], v1 = values2[i % n], v2 = values2[(i + 1) % n], v3 = values2[(i + 2) % n];
    return basis((t - i / n) * n, v0, v1, v2, v3);
  };
}

// node_modules/d3-interpolate/src/constant.js
var constant_default3 = (x3) => () => x3;

// node_modules/d3-interpolate/src/color.js
function linear(a2, d) {
  return function(t) {
    return a2 + t * d;
  };
}
function exponential(a2, b, y3) {
  return a2 = Math.pow(a2, y3), b = Math.pow(b, y3) - a2, y3 = 1 / y3, function(t) {
    return Math.pow(a2 + t * b, y3);
  };
}
function hue(a2, b) {
  var d = b - a2;
  return d ? linear(a2, d > 180 || d < -180 ? d - 360 * Math.round(d / 360) : d) : constant_default3(isNaN(a2) ? b : a2);
}
function gamma(y3) {
  return (y3 = +y3) === 1 ? nogamma : function(a2, b) {
    return b - a2 ? exponential(a2, b, y3) : constant_default3(isNaN(a2) ? b : a2);
  };
}
function nogamma(a2, b) {
  var d = b - a2;
  return d ? linear(a2, d) : constant_default3(isNaN(a2) ? b : a2);
}

// node_modules/d3-interpolate/src/rgb.js
var rgb_default = (function rgbGamma(y3) {
  var color3 = gamma(y3);
  function rgb2(start2, end) {
    var r = color3((start2 = rgb(start2)).r, (end = rgb(end)).r), g = color3(start2.g, end.g), b = color3(start2.b, end.b), opacity2 = nogamma(start2.opacity, end.opacity);
    return function(t) {
      start2.r = r(t);
      start2.g = g(t);
      start2.b = b(t);
      start2.opacity = opacity2(t);
      return start2 + "";
    };
  }
  rgb2.gamma = rgbGamma;
  return rgb2;
})(1);
function rgbSpline(spline) {
  return function(colors) {
    var n = colors.length, r = new Array(n), g = new Array(n), b = new Array(n), i, color3;
    for (i = 0; i < n; ++i) {
      color3 = rgb(colors[i]);
      r[i] = color3.r || 0;
      g[i] = color3.g || 0;
      b[i] = color3.b || 0;
    }
    r = spline(r);
    g = spline(g);
    b = spline(b);
    color3.opacity = 1;
    return function(t) {
      color3.r = r(t);
      color3.g = g(t);
      color3.b = b(t);
      return color3 + "";
    };
  };
}
var rgbBasis = rgbSpline(basis_default);
var rgbBasisClosed = rgbSpline(basisClosed_default);

// node_modules/d3-interpolate/src/numberArray.js
function numberArray_default(a2, b) {
  if (!b) b = [];
  var n = a2 ? Math.min(b.length, a2.length) : 0, c4 = b.slice(), i;
  return function(t) {
    for (i = 0; i < n; ++i) c4[i] = a2[i] * (1 - t) + b[i] * t;
    return c4;
  };
}
function isNumberArray(x3) {
  return ArrayBuffer.isView(x3) && !(x3 instanceof DataView);
}

// node_modules/d3-interpolate/src/array.js
function genericArray(a2, b) {
  var nb = b ? b.length : 0, na = a2 ? Math.min(nb, a2.length) : 0, x3 = new Array(na), c4 = new Array(nb), i;
  for (i = 0; i < na; ++i) x3[i] = value_default(a2[i], b[i]);
  for (; i < nb; ++i) c4[i] = b[i];
  return function(t) {
    for (i = 0; i < na; ++i) c4[i] = x3[i](t);
    return c4;
  };
}

// node_modules/d3-interpolate/src/date.js
function date_default(a2, b) {
  var d = /* @__PURE__ */ new Date();
  return a2 = +a2, b = +b, function(t) {
    return d.setTime(a2 * (1 - t) + b * t), d;
  };
}

// node_modules/d3-interpolate/src/number.js
function number_default(a2, b) {
  return a2 = +a2, b = +b, function(t) {
    return a2 * (1 - t) + b * t;
  };
}

// node_modules/d3-interpolate/src/object.js
function object_default(a2, b) {
  var i = {}, c4 = {}, k2;
  if (a2 === null || typeof a2 !== "object") a2 = {};
  if (b === null || typeof b !== "object") b = {};
  for (k2 in b) {
    if (k2 in a2) {
      i[k2] = value_default(a2[k2], b[k2]);
    } else {
      c4[k2] = b[k2];
    }
  }
  return function(t) {
    for (k2 in i) c4[k2] = i[k2](t);
    return c4;
  };
}

// node_modules/d3-interpolate/src/string.js
var reA = /[-+]?(?:\d+\.?\d*|\.?\d+)(?:[eE][-+]?\d+)?/g;
var reB = new RegExp(reA.source, "g");
function zero2(b) {
  return function() {
    return b;
  };
}
function one(b) {
  return function(t) {
    return b(t) + "";
  };
}
function string_default(a2, b) {
  var bi = reA.lastIndex = reB.lastIndex = 0, am, bm, bs, i = -1, s2 = [], q = [];
  a2 = a2 + "", b = b + "";
  while ((am = reA.exec(a2)) && (bm = reB.exec(b))) {
    if ((bs = bm.index) > bi) {
      bs = b.slice(bi, bs);
      if (s2[i]) s2[i] += bs;
      else s2[++i] = bs;
    }
    if ((am = am[0]) === (bm = bm[0])) {
      if (s2[i]) s2[i] += bm;
      else s2[++i] = bm;
    } else {
      s2[++i] = null;
      q.push({ i, x: number_default(am, bm) });
    }
    bi = reB.lastIndex;
  }
  if (bi < b.length) {
    bs = b.slice(bi);
    if (s2[i]) s2[i] += bs;
    else s2[++i] = bs;
  }
  return s2.length < 2 ? q[0] ? one(q[0].x) : zero2(b) : (b = q.length, function(t) {
    for (var i2 = 0, o; i2 < b; ++i2) s2[(o = q[i2]).i] = o.x(t);
    return s2.join("");
  });
}

// node_modules/d3-interpolate/src/value.js
function value_default(a2, b) {
  var t = typeof b, c4;
  return b == null || t === "boolean" ? constant_default3(b) : (t === "number" ? number_default : t === "string" ? (c4 = color(b)) ? (b = c4, rgb_default) : string_default : b instanceof color ? rgb_default : b instanceof Date ? date_default : isNumberArray(b) ? numberArray_default : Array.isArray(b) ? genericArray : typeof b.valueOf !== "function" && typeof b.toString !== "function" || isNaN(b) ? object_default : number_default)(a2, b);
}

// node_modules/d3-interpolate/src/round.js
function round_default(a2, b) {
  return a2 = +a2, b = +b, function(t) {
    return Math.round(a2 * (1 - t) + b * t);
  };
}

// node_modules/d3-interpolate/src/transform/decompose.js
var degrees2 = 180 / Math.PI;
var identity2 = {
  translateX: 0,
  translateY: 0,
  rotate: 0,
  skewX: 0,
  scaleX: 1,
  scaleY: 1
};
function decompose_default(a2, b, c4, d, e, f) {
  var scaleX, scaleY, skewX;
  if (scaleX = Math.sqrt(a2 * a2 + b * b)) a2 /= scaleX, b /= scaleX;
  if (skewX = a2 * c4 + b * d) c4 -= a2 * skewX, d -= b * skewX;
  if (scaleY = Math.sqrt(c4 * c4 + d * d)) c4 /= scaleY, d /= scaleY, skewX /= scaleY;
  if (a2 * d < b * c4) a2 = -a2, b = -b, skewX = -skewX, scaleX = -scaleX;
  return {
    translateX: e,
    translateY: f,
    rotate: Math.atan2(b, a2) * degrees2,
    skewX: Math.atan(skewX) * degrees2,
    scaleX,
    scaleY
  };
}

// node_modules/d3-interpolate/src/transform/parse.js
var svgNode;
function parseCss(value) {
  const m = new (typeof DOMMatrix === "function" ? DOMMatrix : WebKitCSSMatrix)(value + "");
  return m.isIdentity ? identity2 : decompose_default(m.a, m.b, m.c, m.d, m.e, m.f);
}
function parseSvg(value) {
  if (value == null) return identity2;
  if (!svgNode) svgNode = document.createElementNS("http://www.w3.org/2000/svg", "g");
  svgNode.setAttribute("transform", value);
  if (!(value = svgNode.transform.baseVal.consolidate())) return identity2;
  value = value.matrix;
  return decompose_default(value.a, value.b, value.c, value.d, value.e, value.f);
}

// node_modules/d3-interpolate/src/transform/index.js
function interpolateTransform(parse2, pxComma, pxParen, degParen) {
  function pop(s2) {
    return s2.length ? s2.pop() + " " : "";
  }
  function translate(xa, ya, xb, yb, s2, q) {
    if (xa !== xb || ya !== yb) {
      var i = s2.push("translate(", null, pxComma, null, pxParen);
      q.push({ i: i - 4, x: number_default(xa, xb) }, { i: i - 2, x: number_default(ya, yb) });
    } else if (xb || yb) {
      s2.push("translate(" + xb + pxComma + yb + pxParen);
    }
  }
  function rotate(a2, b, s2, q) {
    if (a2 !== b) {
      if (a2 - b > 180) b += 360;
      else if (b - a2 > 180) a2 += 360;
      q.push({ i: s2.push(pop(s2) + "rotate(", null, degParen) - 2, x: number_default(a2, b) });
    } else if (b) {
      s2.push(pop(s2) + "rotate(" + b + degParen);
    }
  }
  function skewX(a2, b, s2, q) {
    if (a2 !== b) {
      q.push({ i: s2.push(pop(s2) + "skewX(", null, degParen) - 2, x: number_default(a2, b) });
    } else if (b) {
      s2.push(pop(s2) + "skewX(" + b + degParen);
    }
  }
  function scale3(xa, ya, xb, yb, s2, q) {
    if (xa !== xb || ya !== yb) {
      var i = s2.push(pop(s2) + "scale(", null, ",", null, ")");
      q.push({ i: i - 4, x: number_default(xa, xb) }, { i: i - 2, x: number_default(ya, yb) });
    } else if (xb !== 1 || yb !== 1) {
      s2.push(pop(s2) + "scale(" + xb + "," + yb + ")");
    }
  }
  return function(a2, b) {
    var s2 = [], q = [];
    a2 = parse2(a2), b = parse2(b);
    translate(a2.translateX, a2.translateY, b.translateX, b.translateY, s2, q);
    rotate(a2.rotate, b.rotate, s2, q);
    skewX(a2.skewX, b.skewX, s2, q);
    scale3(a2.scaleX, a2.scaleY, b.scaleX, b.scaleY, s2, q);
    a2 = b = null;
    return function(t) {
      var i = -1, n = q.length, o;
      while (++i < n) s2[(o = q[i]).i] = o.x(t);
      return s2.join("");
    };
  };
}
var interpolateTransformCss = interpolateTransform(parseCss, "px, ", "px)", "deg)");
var interpolateTransformSvg = interpolateTransform(parseSvg, ", ", ")", ")");

// node_modules/d3-interpolate/src/zoom.js
var epsilon2 = 1e-12;
function cosh(x3) {
  return ((x3 = Math.exp(x3)) + 1 / x3) / 2;
}
function sinh(x3) {
  return ((x3 = Math.exp(x3)) - 1 / x3) / 2;
}
function tanh(x3) {
  return ((x3 = Math.exp(2 * x3)) - 1) / (x3 + 1);
}
var zoom_default = (function zoomRho(rho, rho2, rho4) {
  function zoom(p0, p1) {
    var ux0 = p0[0], uy0 = p0[1], w0 = p0[2], ux1 = p1[0], uy1 = p1[1], w1 = p1[2], dx = ux1 - ux0, dy = uy1 - uy0, d2 = dx * dx + dy * dy, i, S;
    if (d2 < epsilon2) {
      S = Math.log(w1 / w0) / rho;
      i = function(t) {
        return [
          ux0 + t * dx,
          uy0 + t * dy,
          w0 * Math.exp(rho * t * S)
        ];
      };
    } else {
      var d1 = Math.sqrt(d2), b02 = (w1 * w1 - w0 * w0 + rho4 * d2) / (2 * w0 * rho2 * d1), b12 = (w1 * w1 - w0 * w0 - rho4 * d2) / (2 * w1 * rho2 * d1), r0 = Math.log(Math.sqrt(b02 * b02 + 1) - b02), r1 = Math.log(Math.sqrt(b12 * b12 + 1) - b12);
      S = (r1 - r0) / rho;
      i = function(t) {
        var s2 = t * S, coshr0 = cosh(r0), u4 = w0 / (rho2 * d1) * (coshr0 * tanh(rho * s2 + r0) - sinh(r0));
        return [
          ux0 + u4 * dx,
          uy0 + u4 * dy,
          w0 * coshr0 / cosh(rho * s2 + r0)
        ];
      };
    }
    i.duration = S * 1e3 * rho / Math.SQRT2;
    return i;
  }
  zoom.rho = function(_) {
    var _1 = Math.max(1e-3, +_), _2 = _1 * _1, _4 = _2 * _2;
    return zoomRho(_1, _2, _4);
  };
  return zoom;
})(Math.SQRT2, 2, 4);

// node_modules/d3-interpolate/src/hsl.js
function hsl2(hue2) {
  return function(start2, end) {
    var h = hue2((start2 = hsl(start2)).h, (end = hsl(end)).h), s2 = nogamma(start2.s, end.s), l = nogamma(start2.l, end.l), opacity2 = nogamma(start2.opacity, end.opacity);
    return function(t) {
      start2.h = h(t);
      start2.s = s2(t);
      start2.l = l(t);
      start2.opacity = opacity2(t);
      return start2 + "";
    };
  };
}
var hsl_default = hsl2(hue);
var hslLong = hsl2(nogamma);

// node_modules/d3-interpolate/src/lab.js
function lab2(start2, end) {
  var l = nogamma((start2 = lab(start2)).l, (end = lab(end)).l), a2 = nogamma(start2.a, end.a), b = nogamma(start2.b, end.b), opacity2 = nogamma(start2.opacity, end.opacity);
  return function(t) {
    start2.l = l(t);
    start2.a = a2(t);
    start2.b = b(t);
    start2.opacity = opacity2(t);
    return start2 + "";
  };
}

// node_modules/d3-interpolate/src/hcl.js
function hcl2(hue2) {
  return function(start2, end) {
    var h = hue2((start2 = hcl(start2)).h, (end = hcl(end)).h), c4 = nogamma(start2.c, end.c), l = nogamma(start2.l, end.l), opacity2 = nogamma(start2.opacity, end.opacity);
    return function(t) {
      start2.h = h(t);
      start2.c = c4(t);
      start2.l = l(t);
      start2.opacity = opacity2(t);
      return start2 + "";
    };
  };
}
var hcl_default = hcl2(hue);
var hclLong = hcl2(nogamma);

// node_modules/d3-interpolate/src/cubehelix.js
function cubehelix2(hue2) {
  return (function cubehelixGamma(y3) {
    y3 = +y3;
    function cubehelix3(start2, end) {
      var h = hue2((start2 = cubehelix(start2)).h, (end = cubehelix(end)).h), s2 = nogamma(start2.s, end.s), l = nogamma(start2.l, end.l), opacity2 = nogamma(start2.opacity, end.opacity);
      return function(t) {
        start2.h = h(t);
        start2.s = s2(t);
        start2.l = l(Math.pow(t, y3));
        start2.opacity = opacity2(t);
        return start2 + "";
      };
    }
    cubehelix3.gamma = cubehelixGamma;
    return cubehelix3;
  })(1);
}
var cubehelix_default = cubehelix2(hue);
var cubehelixLong = cubehelix2(nogamma);

// node_modules/d3-interpolate/src/piecewise.js
function piecewise(interpolate, values2) {
  if (values2 === void 0) values2 = interpolate, interpolate = value_default;
  var i = 0, n = values2.length - 1, v2 = values2[0], I = new Array(n < 0 ? 0 : n);
  while (i < n) I[i] = interpolate(v2, v2 = values2[++i]);
  return function(t) {
    var i2 = Math.max(0, Math.min(n - 1, Math.floor(t *= n)));
    return I[i2](t - i2);
  };
}

// node_modules/d3-interpolate/src/quantize.js
function quantize_default(interpolator, n) {
  var samples = new Array(n);
  for (var i = 0; i < n; ++i) samples[i] = interpolator(i / (n - 1));
  return samples;
}

// node_modules/d3-timer/src/timer.js
var frame = 0;
var timeout = 0;
var interval = 0;
var pokeDelay = 1e3;
var taskHead;
var taskTail;
var clockLast = 0;
var clockNow = 0;
var clockSkew = 0;
var clock = typeof performance === "object" && performance.now ? performance : Date;
var setFrame = typeof window === "object" && window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : function(f) {
  setTimeout(f, 17);
};
function now() {
  return clockNow || (setFrame(clearNow), clockNow = clock.now() + clockSkew);
}
function clearNow() {
  clockNow = 0;
}
function Timer() {
  this._call = this._time = this._next = null;
}
Timer.prototype = timer.prototype = {
  constructor: Timer,
  restart: function(callback, delay, time2) {
    if (typeof callback !== "function") throw new TypeError("callback is not a function");
    time2 = (time2 == null ? now() : +time2) + (delay == null ? 0 : +delay);
    if (!this._next && taskTail !== this) {
      if (taskTail) taskTail._next = this;
      else taskHead = this;
      taskTail = this;
    }
    this._call = callback;
    this._time = time2;
    sleep();
  },
  stop: function() {
    if (this._call) {
      this._call = null;
      this._time = Infinity;
      sleep();
    }
  }
};
function timer(callback, delay, time2) {
  var t = new Timer();
  t.restart(callback, delay, time2);
  return t;
}
function timerFlush() {
  now();
  ++frame;
  var t = taskHead, e;
  while (t) {
    if ((e = clockNow - t._time) >= 0) t._call.call(void 0, e);
    t = t._next;
  }
  --frame;
}
function wake() {
  clockNow = (clockLast = clock.now()) + clockSkew;
  frame = timeout = 0;
  try {
    timerFlush();
  } finally {
    frame = 0;
    nap();
    clockNow = 0;
  }
}
function poke() {
  var now2 = clock.now(), delay = now2 - clockLast;
  if (delay > pokeDelay) clockSkew -= delay, clockLast = now2;
}
function nap() {
  var t03, t13 = taskHead, t22, time2 = Infinity;
  while (t13) {
    if (t13._call) {
      if (time2 > t13._time) time2 = t13._time;
      t03 = t13, t13 = t13._next;
    } else {
      t22 = t13._next, t13._next = null;
      t13 = t03 ? t03._next = t22 : taskHead = t22;
    }
  }
  taskTail = t03;
  sleep(time2);
}
function sleep(time2) {
  if (frame) return;
  if (timeout) timeout = clearTimeout(timeout);
  var delay = time2 - clockNow;
  if (delay > 24) {
    if (time2 < Infinity) timeout = setTimeout(wake, time2 - clock.now() - clockSkew);
    if (interval) interval = clearInterval(interval);
  } else {
    if (!interval) clockLast = clock.now(), interval = setInterval(poke, pokeDelay);
    frame = 1, setFrame(wake);
  }
}

// node_modules/d3-timer/src/timeout.js
function timeout_default(callback, delay, time2) {
  var t = new Timer();
  delay = delay == null ? 0 : +delay;
  t.restart((elapsed) => {
    t.stop();
    callback(elapsed + delay);
  }, delay, time2);
  return t;
}

// node_modules/d3-transition/src/transition/schedule.js
var emptyOn = dispatch_default("start", "end", "cancel", "interrupt");
var emptyTween = [];
var CREATED = 0;
var SCHEDULED = 1;
var STARTING = 2;
var STARTED = 3;
var RUNNING = 4;
var ENDING = 5;
var ENDED = 6;
function schedule_default(node, name, id2, index2, group3, timing) {
  var schedules = node.__transition;
  if (!schedules) node.__transition = {};
  else if (id2 in schedules) return;
  create(node, id2, {
    name,
    index: index2,
    // For context during callback.
    group: group3,
    // For context during callback.
    on: emptyOn,
    tween: emptyTween,
    time: timing.time,
    delay: timing.delay,
    duration: timing.duration,
    ease: timing.ease,
    timer: null,
    state: CREATED
  });
}
function init(node, id2) {
  var schedule = get2(node, id2);
  if (schedule.state > CREATED) throw new Error("too late; already scheduled");
  return schedule;
}
function set2(node, id2) {
  var schedule = get2(node, id2);
  if (schedule.state > STARTED) throw new Error("too late; already running");
  return schedule;
}
function get2(node, id2) {
  var schedule = node.__transition;
  if (!schedule || !(schedule = schedule[id2])) throw new Error("transition not found");
  return schedule;
}
function create(node, id2, self) {
  var schedules = node.__transition, tween;
  schedules[id2] = self;
  self.timer = timer(schedule, 0, self.time);
  function schedule(elapsed) {
    self.state = SCHEDULED;
    self.timer.restart(start2, self.delay, self.time);
    if (self.delay <= elapsed) start2(elapsed - self.delay);
  }
  function start2(elapsed) {
    var i, j, n, o;
    if (self.state !== SCHEDULED) return stop();
    for (i in schedules) {
      o = schedules[i];
      if (o.name !== self.name) continue;
      if (o.state === STARTED) return timeout_default(start2);
      if (o.state === RUNNING) {
        o.state = ENDED;
        o.timer.stop();
        o.on.call("interrupt", node, node.__data__, o.index, o.group);
        delete schedules[i];
      } else if (+i < id2) {
        o.state = ENDED;
        o.timer.stop();
        o.on.call("cancel", node, node.__data__, o.index, o.group);
        delete schedules[i];
      }
    }
    timeout_default(function() {
      if (self.state === STARTED) {
        self.state = RUNNING;
        self.timer.restart(tick, self.delay, self.time);
        tick(elapsed);
      }
    });
    self.state = STARTING;
    self.on.call("start", node, node.__data__, self.index, self.group);
    if (self.state !== STARTING) return;
    self.state = STARTED;
    tween = new Array(n = self.tween.length);
    for (i = 0, j = -1; i < n; ++i) {
      if (o = self.tween[i].value.call(node, node.__data__, self.index, self.group)) {
        tween[++j] = o;
      }
    }
    tween.length = j + 1;
  }
  function tick(elapsed) {
    var t = elapsed < self.duration ? self.ease.call(null, elapsed / self.duration) : (self.timer.restart(stop), self.state = ENDING, 1), i = -1, n = tween.length;
    while (++i < n) {
      tween[i].call(node, t);
    }
    if (self.state === ENDING) {
      self.on.call("end", node, node.__data__, self.index, self.group);
      stop();
    }
  }
  function stop() {
    self.state = ENDED;
    self.timer.stop();
    delete schedules[id2];
    for (var i in schedules) return;
    delete node.__transition;
  }
}

// node_modules/d3-transition/src/interrupt.js
function interrupt_default(node, name) {
  var schedules = node.__transition, schedule, active, empty3 = true, i;
  if (!schedules) return;
  name = name == null ? null : name + "";
  for (i in schedules) {
    if ((schedule = schedules[i]).name !== name) {
      empty3 = false;
      continue;
    }
    active = schedule.state > STARTING && schedule.state < ENDING;
    schedule.state = ENDED;
    schedule.timer.stop();
    schedule.on.call(active ? "interrupt" : "cancel", node, node.__data__, schedule.index, schedule.group);
    delete schedules[i];
  }
  if (empty3) delete node.__transition;
}

// node_modules/d3-transition/src/selection/interrupt.js
function interrupt_default2(name) {
  return this.each(function() {
    interrupt_default(this, name);
  });
}

// node_modules/d3-transition/src/transition/tween.js
function tweenRemove(id2, name) {
  var tween0, tween1;
  return function() {
    var schedule = set2(this, id2), tween = schedule.tween;
    if (tween !== tween0) {
      tween1 = tween0 = tween;
      for (var i = 0, n = tween1.length; i < n; ++i) {
        if (tween1[i].name === name) {
          tween1 = tween1.slice();
          tween1.splice(i, 1);
          break;
        }
      }
    }
    schedule.tween = tween1;
  };
}
function tweenFunction(id2, name, value) {
  var tween0, tween1;
  if (typeof value !== "function") throw new Error();
  return function() {
    var schedule = set2(this, id2), tween = schedule.tween;
    if (tween !== tween0) {
      tween1 = (tween0 = tween).slice();
      for (var t = { name, value }, i = 0, n = tween1.length; i < n; ++i) {
        if (tween1[i].name === name) {
          tween1[i] = t;
          break;
        }
      }
      if (i === n) tween1.push(t);
    }
    schedule.tween = tween1;
  };
}
function tween_default(name, value) {
  var id2 = this._id;
  name += "";
  if (arguments.length < 2) {
    var tween = get2(this.node(), id2).tween;
    for (var i = 0, n = tween.length, t; i < n; ++i) {
      if ((t = tween[i]).name === name) {
        return t.value;
      }
    }
    return null;
  }
  return this.each((value == null ? tweenRemove : tweenFunction)(id2, name, value));
}
function tweenValue(transition2, name, value) {
  var id2 = transition2._id;
  transition2.each(function() {
    var schedule = set2(this, id2);
    (schedule.value || (schedule.value = {}))[name] = value.apply(this, arguments);
  });
  return function(node) {
    return get2(node, id2).value[name];
  };
}

// node_modules/d3-transition/src/transition/interpolate.js
function interpolate_default(a2, b) {
  var c4;
  return (typeof b === "number" ? number_default : b instanceof color ? rgb_default : (c4 = color(b)) ? (b = c4, rgb_default) : string_default)(a2, b);
}

// node_modules/d3-transition/src/transition/attr.js
function attrRemove2(name) {
  return function() {
    this.removeAttribute(name);
  };
}
function attrRemoveNS2(fullname) {
  return function() {
    this.removeAttributeNS(fullname.space, fullname.local);
  };
}
function attrConstant2(name, interpolate, value1) {
  var string00, string1 = value1 + "", interpolate0;
  return function() {
    var string0 = this.getAttribute(name);
    return string0 === string1 ? null : string0 === string00 ? interpolate0 : interpolate0 = interpolate(string00 = string0, value1);
  };
}
function attrConstantNS2(fullname, interpolate, value1) {
  var string00, string1 = value1 + "", interpolate0;
  return function() {
    var string0 = this.getAttributeNS(fullname.space, fullname.local);
    return string0 === string1 ? null : string0 === string00 ? interpolate0 : interpolate0 = interpolate(string00 = string0, value1);
  };
}
function attrFunction2(name, interpolate, value) {
  var string00, string10, interpolate0;
  return function() {
    var string0, value1 = value(this), string1;
    if (value1 == null) return void this.removeAttribute(name);
    string0 = this.getAttribute(name);
    string1 = value1 + "";
    return string0 === string1 ? null : string0 === string00 && string1 === string10 ? interpolate0 : (string10 = string1, interpolate0 = interpolate(string00 = string0, value1));
  };
}
function attrFunctionNS2(fullname, interpolate, value) {
  var string00, string10, interpolate0;
  return function() {
    var string0, value1 = value(this), string1;
    if (value1 == null) return void this.removeAttributeNS(fullname.space, fullname.local);
    string0 = this.getAttributeNS(fullname.space, fullname.local);
    string1 = value1 + "";
    return string0 === string1 ? null : string0 === string00 && string1 === string10 ? interpolate0 : (string10 = string1, interpolate0 = interpolate(string00 = string0, value1));
  };
}
function attr_default2(name, value) {
  var fullname = namespace_default(name), i = fullname === "transform" ? interpolateTransformSvg : interpolate_default;
  return this.attrTween(name, typeof value === "function" ? (fullname.local ? attrFunctionNS2 : attrFunction2)(fullname, i, tweenValue(this, "attr." + name, value)) : value == null ? (fullname.local ? attrRemoveNS2 : attrRemove2)(fullname) : (fullname.local ? attrConstantNS2 : attrConstant2)(fullname, i, value));
}

// node_modules/d3-transition/src/transition/attrTween.js
function attrInterpolate(name, i) {
  return function(t) {
    this.setAttribute(name, i.call(this, t));
  };
}
function attrInterpolateNS(fullname, i) {
  return function(t) {
    this.setAttributeNS(fullname.space, fullname.local, i.call(this, t));
  };
}
function attrTweenNS(fullname, value) {
  var t03, i0;
  function tween() {
    var i = value.apply(this, arguments);
    if (i !== i0) t03 = (i0 = i) && attrInterpolateNS(fullname, i);
    return t03;
  }
  tween._value = value;
  return tween;
}
function attrTween(name, value) {
  var t03, i0;
  function tween() {
    var i = value.apply(this, arguments);
    if (i !== i0) t03 = (i0 = i) && attrInterpolate(name, i);
    return t03;
  }
  tween._value = value;
  return tween;
}
function attrTween_default(name, value) {
  var key = "attr." + name;
  if (arguments.length < 2) return (key = this.tween(key)) && key._value;
  if (value == null) return this.tween(key, null);
  if (typeof value !== "function") throw new Error();
  var fullname = namespace_default(name);
  return this.tween(key, (fullname.local ? attrTweenNS : attrTween)(fullname, value));
}

// node_modules/d3-transition/src/transition/delay.js
function delayFunction(id2, value) {
  return function() {
    init(this, id2).delay = +value.apply(this, arguments);
  };
}
function delayConstant(id2, value) {
  return value = +value, function() {
    init(this, id2).delay = value;
  };
}
function delay_default(value) {
  var id2 = this._id;
  return arguments.length ? this.each((typeof value === "function" ? delayFunction : delayConstant)(id2, value)) : get2(this.node(), id2).delay;
}

// node_modules/d3-transition/src/transition/duration.js
function durationFunction(id2, value) {
  return function() {
    set2(this, id2).duration = +value.apply(this, arguments);
  };
}
function durationConstant(id2, value) {
  return value = +value, function() {
    set2(this, id2).duration = value;
  };
}
function duration_default(value) {
  var id2 = this._id;
  return arguments.length ? this.each((typeof value === "function" ? durationFunction : durationConstant)(id2, value)) : get2(this.node(), id2).duration;
}

// node_modules/d3-transition/src/transition/ease.js
function easeConstant(id2, value) {
  if (typeof value !== "function") throw new Error();
  return function() {
    set2(this, id2).ease = value;
  };
}
function ease_default(value) {
  var id2 = this._id;
  return arguments.length ? this.each(easeConstant(id2, value)) : get2(this.node(), id2).ease;
}

// node_modules/d3-transition/src/transition/easeVarying.js
function easeVarying(id2, value) {
  return function() {
    var v2 = value.apply(this, arguments);
    if (typeof v2 !== "function") throw new Error();
    set2(this, id2).ease = v2;
  };
}
function easeVarying_default(value) {
  if (typeof value !== "function") throw new Error();
  return this.each(easeVarying(this._id, value));
}

// node_modules/d3-transition/src/transition/filter.js
function filter_default2(match) {
  if (typeof match !== "function") match = matcher_default(match);
  for (var groups2 = this._groups, m = groups2.length, subgroups = new Array(m), j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, subgroup = subgroups[j] = [], node, i = 0; i < n; ++i) {
      if ((node = group3[i]) && match.call(node, node.__data__, i, group3)) {
        subgroup.push(node);
      }
    }
  }
  return new Transition(subgroups, this._parents, this._name, this._id);
}

// node_modules/d3-transition/src/transition/merge.js
function merge_default2(transition2) {
  if (transition2._id !== this._id) throw new Error();
  for (var groups0 = this._groups, groups1 = transition2._groups, m0 = groups0.length, m1 = groups1.length, m = Math.min(m0, m1), merges = new Array(m0), j = 0; j < m; ++j) {
    for (var group0 = groups0[j], group1 = groups1[j], n = group0.length, merge2 = merges[j] = new Array(n), node, i = 0; i < n; ++i) {
      if (node = group0[i] || group1[i]) {
        merge2[i] = node;
      }
    }
  }
  for (; j < m0; ++j) {
    merges[j] = groups0[j];
  }
  return new Transition(merges, this._parents, this._name, this._id);
}

// node_modules/d3-transition/src/transition/on.js
function start(name) {
  return (name + "").trim().split(/^|\s+/).every(function(t) {
    var i = t.indexOf(".");
    if (i >= 0) t = t.slice(0, i);
    return !t || t === "start";
  });
}
function onFunction(id2, name, listener) {
  var on0, on1, sit = start(name) ? init : set2;
  return function() {
    var schedule = sit(this, id2), on = schedule.on;
    if (on !== on0) (on1 = (on0 = on).copy()).on(name, listener);
    schedule.on = on1;
  };
}
function on_default2(name, listener) {
  var id2 = this._id;
  return arguments.length < 2 ? get2(this.node(), id2).on.on(name) : this.each(onFunction(id2, name, listener));
}

// node_modules/d3-transition/src/transition/remove.js
function removeFunction(id2) {
  return function() {
    var parent = this.parentNode;
    for (var i in this.__transition) if (+i !== id2) return;
    if (parent) parent.removeChild(this);
  };
}
function remove_default2() {
  return this.on("end.remove", removeFunction(this._id));
}

// node_modules/d3-transition/src/transition/select.js
function select_default3(select2) {
  var name = this._name, id2 = this._id;
  if (typeof select2 !== "function") select2 = selector_default(select2);
  for (var groups2 = this._groups, m = groups2.length, subgroups = new Array(m), j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, subgroup = subgroups[j] = new Array(n), node, subnode, i = 0; i < n; ++i) {
      if ((node = group3[i]) && (subnode = select2.call(node, node.__data__, i, group3))) {
        if ("__data__" in node) subnode.__data__ = node.__data__;
        subgroup[i] = subnode;
        schedule_default(subgroup[i], name, id2, i, subgroup, get2(node, id2));
      }
    }
  }
  return new Transition(subgroups, this._parents, name, id2);
}

// node_modules/d3-transition/src/transition/selectAll.js
function selectAll_default3(select2) {
  var name = this._name, id2 = this._id;
  if (typeof select2 !== "function") select2 = selectorAll_default(select2);
  for (var groups2 = this._groups, m = groups2.length, subgroups = [], parents = [], j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, node, i = 0; i < n; ++i) {
      if (node = group3[i]) {
        for (var children2 = select2.call(node, node.__data__, i, group3), child, inherit3 = get2(node, id2), k2 = 0, l = children2.length; k2 < l; ++k2) {
          if (child = children2[k2]) {
            schedule_default(child, name, id2, k2, children2, inherit3);
          }
        }
        subgroups.push(children2);
        parents.push(node);
      }
    }
  }
  return new Transition(subgroups, parents, name, id2);
}

// node_modules/d3-transition/src/transition/selection.js
var Selection2 = selection_default.prototype.constructor;
function selection_default2() {
  return new Selection2(this._groups, this._parents);
}

// node_modules/d3-transition/src/transition/style.js
function styleNull(name, interpolate) {
  var string00, string10, interpolate0;
  return function() {
    var string0 = styleValue(this, name), string1 = (this.style.removeProperty(name), styleValue(this, name));
    return string0 === string1 ? null : string0 === string00 && string1 === string10 ? interpolate0 : interpolate0 = interpolate(string00 = string0, string10 = string1);
  };
}
function styleRemove2(name) {
  return function() {
    this.style.removeProperty(name);
  };
}
function styleConstant2(name, interpolate, value1) {
  var string00, string1 = value1 + "", interpolate0;
  return function() {
    var string0 = styleValue(this, name);
    return string0 === string1 ? null : string0 === string00 ? interpolate0 : interpolate0 = interpolate(string00 = string0, value1);
  };
}
function styleFunction2(name, interpolate, value) {
  var string00, string10, interpolate0;
  return function() {
    var string0 = styleValue(this, name), value1 = value(this), string1 = value1 + "";
    if (value1 == null) string1 = value1 = (this.style.removeProperty(name), styleValue(this, name));
    return string0 === string1 ? null : string0 === string00 && string1 === string10 ? interpolate0 : (string10 = string1, interpolate0 = interpolate(string00 = string0, value1));
  };
}
function styleMaybeRemove(id2, name) {
  var on0, on1, listener0, key = "style." + name, event = "end." + key, remove2;
  return function() {
    var schedule = set2(this, id2), on = schedule.on, listener = schedule.value[key] == null ? remove2 || (remove2 = styleRemove2(name)) : void 0;
    if (on !== on0 || listener0 !== listener) (on1 = (on0 = on).copy()).on(event, listener0 = listener);
    schedule.on = on1;
  };
}
function style_default2(name, value, priority) {
  var i = (name += "") === "transform" ? interpolateTransformCss : interpolate_default;
  return value == null ? this.styleTween(name, styleNull(name, i)).on("end.style." + name, styleRemove2(name)) : typeof value === "function" ? this.styleTween(name, styleFunction2(name, i, tweenValue(this, "style." + name, value))).each(styleMaybeRemove(this._id, name)) : this.styleTween(name, styleConstant2(name, i, value), priority).on("end.style." + name, null);
}

// node_modules/d3-transition/src/transition/styleTween.js
function styleInterpolate(name, i, priority) {
  return function(t) {
    this.style.setProperty(name, i.call(this, t), priority);
  };
}
function styleTween(name, value, priority) {
  var t, i0;
  function tween() {
    var i = value.apply(this, arguments);
    if (i !== i0) t = (i0 = i) && styleInterpolate(name, i, priority);
    return t;
  }
  tween._value = value;
  return tween;
}
function styleTween_default(name, value, priority) {
  var key = "style." + (name += "");
  if (arguments.length < 2) return (key = this.tween(key)) && key._value;
  if (value == null) return this.tween(key, null);
  if (typeof value !== "function") throw new Error();
  return this.tween(key, styleTween(name, value, priority == null ? "" : priority));
}

// node_modules/d3-transition/src/transition/text.js
function textConstant2(value) {
  return function() {
    this.textContent = value;
  };
}
function textFunction2(value) {
  return function() {
    var value1 = value(this);
    this.textContent = value1 == null ? "" : value1;
  };
}
function text_default2(value) {
  return this.tween("text", typeof value === "function" ? textFunction2(tweenValue(this, "text", value)) : textConstant2(value == null ? "" : value + ""));
}

// node_modules/d3-transition/src/transition/textTween.js
function textInterpolate(i) {
  return function(t) {
    this.textContent = i.call(this, t);
  };
}
function textTween(value) {
  var t03, i0;
  function tween() {
    var i = value.apply(this, arguments);
    if (i !== i0) t03 = (i0 = i) && textInterpolate(i);
    return t03;
  }
  tween._value = value;
  return tween;
}
function textTween_default(value) {
  var key = "text";
  if (arguments.length < 1) return (key = this.tween(key)) && key._value;
  if (value == null) return this.tween(key, null);
  if (typeof value !== "function") throw new Error();
  return this.tween(key, textTween(value));
}

// node_modules/d3-transition/src/transition/transition.js
function transition_default() {
  var name = this._name, id0 = this._id, id1 = newId();
  for (var groups2 = this._groups, m = groups2.length, j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, node, i = 0; i < n; ++i) {
      if (node = group3[i]) {
        var inherit3 = get2(node, id0);
        schedule_default(node, name, id1, i, group3, {
          time: inherit3.time + inherit3.delay + inherit3.duration,
          delay: 0,
          duration: inherit3.duration,
          ease: inherit3.ease
        });
      }
    }
  }
  return new Transition(groups2, this._parents, name, id1);
}

// node_modules/d3-transition/src/transition/end.js
function end_default() {
  var on0, on1, that = this, id2 = that._id, size = that.size();
  return new Promise(function(resolve, reject) {
    var cancel = { value: reject }, end = { value: function() {
      if (--size === 0) resolve();
    } };
    that.each(function() {
      var schedule = set2(this, id2), on = schedule.on;
      if (on !== on0) {
        on1 = (on0 = on).copy();
        on1._.cancel.push(cancel);
        on1._.interrupt.push(cancel);
        on1._.end.push(end);
      }
      schedule.on = on1;
    });
    if (size === 0) resolve();
  });
}

// node_modules/d3-transition/src/transition/index.js
var id = 0;
function Transition(groups2, parents, name, id2) {
  this._groups = groups2;
  this._parents = parents;
  this._name = name;
  this._id = id2;
}
function transition(name) {
  return selection_default().transition(name);
}
function newId() {
  return ++id;
}
var selection_prototype = selection_default.prototype;
Transition.prototype = transition.prototype = {
  constructor: Transition,
  select: select_default3,
  selectAll: selectAll_default3,
  selectChild: selection_prototype.selectChild,
  selectChildren: selection_prototype.selectChildren,
  filter: filter_default2,
  merge: merge_default2,
  selection: selection_default2,
  transition: transition_default,
  call: selection_prototype.call,
  nodes: selection_prototype.nodes,
  node: selection_prototype.node,
  size: selection_prototype.size,
  empty: selection_prototype.empty,
  each: selection_prototype.each,
  on: on_default2,
  attr: attr_default2,
  attrTween: attrTween_default,
  style: style_default2,
  styleTween: styleTween_default,
  text: text_default2,
  textTween: textTween_default,
  remove: remove_default2,
  tween: tween_default,
  delay: delay_default,
  duration: duration_default,
  ease: ease_default,
  easeVarying: easeVarying_default,
  end: end_default,
  [Symbol.iterator]: selection_prototype[Symbol.iterator]
};

// node_modules/d3-ease/src/cubic.js
function cubicInOut(t) {
  return ((t *= 2) <= 1 ? t * t * t : (t -= 2) * t * t + 2) / 2;
}

// node_modules/d3-ease/src/poly.js
var exponent = 3;
var polyIn = (function custom(e) {
  e = +e;
  function polyIn2(t) {
    return Math.pow(t, e);
  }
  polyIn2.exponent = custom;
  return polyIn2;
})(exponent);
var polyOut = (function custom2(e) {
  e = +e;
  function polyOut2(t) {
    return 1 - Math.pow(1 - t, e);
  }
  polyOut2.exponent = custom2;
  return polyOut2;
})(exponent);
var polyInOut = (function custom3(e) {
  e = +e;
  function polyInOut2(t) {
    return ((t *= 2) <= 1 ? Math.pow(t, e) : 2 - Math.pow(2 - t, e)) / 2;
  }
  polyInOut2.exponent = custom3;
  return polyInOut2;
})(exponent);

// node_modules/d3-ease/src/sin.js
var pi = Math.PI;
var halfPi = pi / 2;

// node_modules/d3-ease/src/math.js
function tpmt(x3) {
  return (Math.pow(2, -10 * x3) - 9765625e-10) * 1.0009775171065494;
}

// node_modules/d3-ease/src/bounce.js
var b1 = 4 / 11;
var b2 = 6 / 11;
var b3 = 8 / 11;
var b4 = 3 / 4;
var b5 = 9 / 11;
var b6 = 10 / 11;
var b7 = 15 / 16;
var b8 = 21 / 22;
var b9 = 63 / 64;
var b0 = 1 / b1 / b1;

// node_modules/d3-ease/src/back.js
var overshoot = 1.70158;
var backIn = (function custom4(s2) {
  s2 = +s2;
  function backIn2(t) {
    return (t = +t) * t * (s2 * (t - 1) + t);
  }
  backIn2.overshoot = custom4;
  return backIn2;
})(overshoot);
var backOut = (function custom5(s2) {
  s2 = +s2;
  function backOut2(t) {
    return --t * t * ((t + 1) * s2 + t) + 1;
  }
  backOut2.overshoot = custom5;
  return backOut2;
})(overshoot);
var backInOut = (function custom6(s2) {
  s2 = +s2;
  function backInOut2(t) {
    return ((t *= 2) < 1 ? t * t * ((s2 + 1) * t - s2) : (t -= 2) * t * ((s2 + 1) * t + s2) + 2) / 2;
  }
  backInOut2.overshoot = custom6;
  return backInOut2;
})(overshoot);

// node_modules/d3-ease/src/elastic.js
var tau = 2 * Math.PI;
var amplitude = 1;
var period = 0.3;
var elasticIn = (function custom7(a2, p) {
  var s2 = Math.asin(1 / (a2 = Math.max(1, a2))) * (p /= tau);
  function elasticIn2(t) {
    return a2 * tpmt(- --t) * Math.sin((s2 - t) / p);
  }
  elasticIn2.amplitude = function(a3) {
    return custom7(a3, p * tau);
  };
  elasticIn2.period = function(p2) {
    return custom7(a2, p2);
  };
  return elasticIn2;
})(amplitude, period);
var elasticOut = (function custom8(a2, p) {
  var s2 = Math.asin(1 / (a2 = Math.max(1, a2))) * (p /= tau);
  function elasticOut2(t) {
    return 1 - a2 * tpmt(t = +t) * Math.sin((t + s2) / p);
  }
  elasticOut2.amplitude = function(a3) {
    return custom8(a3, p * tau);
  };
  elasticOut2.period = function(p2) {
    return custom8(a2, p2);
  };
  return elasticOut2;
})(amplitude, period);
var elasticInOut = (function custom9(a2, p) {
  var s2 = Math.asin(1 / (a2 = Math.max(1, a2))) * (p /= tau);
  function elasticInOut2(t) {
    return ((t = t * 2 - 1) < 0 ? a2 * tpmt(-t) * Math.sin((s2 - t) / p) : 2 - a2 * tpmt(t) * Math.sin((s2 + t) / p)) / 2;
  }
  elasticInOut2.amplitude = function(a3) {
    return custom9(a3, p * tau);
  };
  elasticInOut2.period = function(p2) {
    return custom9(a2, p2);
  };
  return elasticInOut2;
})(amplitude, period);

// node_modules/d3-transition/src/selection/transition.js
var defaultTiming = {
  time: null,
  // Set on use.
  delay: 0,
  duration: 250,
  ease: cubicInOut
};
function inherit(node, id2) {
  var timing;
  while (!(timing = node.__transition) || !(timing = timing[id2])) {
    if (!(node = node.parentNode)) {
      throw new Error(`transition ${id2} not found`);
    }
  }
  return timing;
}
function transition_default2(name) {
  var id2, timing;
  if (name instanceof Transition) {
    id2 = name._id, name = name._name;
  } else {
    id2 = newId(), (timing = defaultTiming).time = now(), name = name == null ? null : name + "";
  }
  for (var groups2 = this._groups, m = groups2.length, j = 0; j < m; ++j) {
    for (var group3 = groups2[j], n = group3.length, node, i = 0; i < n; ++i) {
      if (node = group3[i]) {
        schedule_default(node, name, id2, i, group3, timing || inherit(node, id2));
      }
    }
  }
  return new Transition(groups2, this._parents, name, id2);
}

// node_modules/d3-transition/src/selection/index.js
selection_default.prototype.interrupt = interrupt_default2;
selection_default.prototype.transition = transition_default2;

// node_modules/d3-brush/src/brush.js
var { abs, max: max2, min: min2 } = Math;
function number1(e) {
  return [+e[0], +e[1]];
}
function number22(e) {
  return [number1(e[0]), number1(e[1])];
}
var X = {
  name: "x",
  handles: ["w", "e"].map(type),
  input: function(x3, e) {
    return x3 == null ? null : [[+x3[0], e[0][1]], [+x3[1], e[1][1]]];
  },
  output: function(xy) {
    return xy && [xy[0][0], xy[1][0]];
  }
};
var Y = {
  name: "y",
  handles: ["n", "s"].map(type),
  input: function(y3, e) {
    return y3 == null ? null : [[e[0][0], +y3[0]], [e[1][0], +y3[1]]];
  },
  output: function(xy) {
    return xy && [xy[0][1], xy[1][1]];
  }
};
var XY = {
  name: "xy",
  handles: ["n", "w", "e", "s", "nw", "ne", "sw", "se"].map(type),
  input: function(xy) {
    return xy == null ? null : number22(xy);
  },
  output: function(xy) {
    return xy;
  }
};
function type(t) {
  return { type: t };
}

// node_modules/d3-chord/src/math.js
var pi2 = Math.PI;
var halfPi2 = pi2 / 2;
var tau2 = pi2 * 2;

// node_modules/d3-path/src/path.js
var pi3 = Math.PI;
var tau3 = 2 * pi3;
var epsilon3 = 1e-6;
var tauEpsilon = tau3 - epsilon3;
function append(strings) {
  this._ += strings[0];
  for (let i = 1, n = strings.length; i < n; ++i) {
    this._ += arguments[i] + strings[i];
  }
}
function appendRound(digits) {
  let d = Math.floor(digits);
  if (!(d >= 0)) throw new Error(`invalid digits: ${digits}`);
  if (d > 15) return append;
  const k2 = 10 ** d;
  return function(strings) {
    this._ += strings[0];
    for (let i = 1, n = strings.length; i < n; ++i) {
      this._ += Math.round(arguments[i] * k2) / k2 + strings[i];
    }
  };
}
var Path = class {
  constructor(digits) {
    this._x0 = this._y0 = // start of current subpath
    this._x1 = this._y1 = null;
    this._ = "";
    this._append = digits == null ? append : appendRound(digits);
  }
  moveTo(x3, y3) {
    this._append`M${this._x0 = this._x1 = +x3},${this._y0 = this._y1 = +y3}`;
  }
  closePath() {
    if (this._x1 !== null) {
      this._x1 = this._x0, this._y1 = this._y0;
      this._append`Z`;
    }
  }
  lineTo(x3, y3) {
    this._append`L${this._x1 = +x3},${this._y1 = +y3}`;
  }
  quadraticCurveTo(x12, y12, x3, y3) {
    this._append`Q${+x12},${+y12},${this._x1 = +x3},${this._y1 = +y3}`;
  }
  bezierCurveTo(x12, y12, x22, y22, x3, y3) {
    this._append`C${+x12},${+y12},${+x22},${+y22},${this._x1 = +x3},${this._y1 = +y3}`;
  }
  arcTo(x12, y12, x22, y22, r) {
    x12 = +x12, y12 = +y12, x22 = +x22, y22 = +y22, r = +r;
    if (r < 0) throw new Error(`negative radius: ${r}`);
    let x06 = this._x1, y06 = this._y1, x21 = x22 - x12, y21 = y22 - y12, x01 = x06 - x12, y01 = y06 - y12, l01_2 = x01 * x01 + y01 * y01;
    if (this._x1 === null) {
      this._append`M${this._x1 = x12},${this._y1 = y12}`;
    } else if (!(l01_2 > epsilon3)) ;
    else if (!(Math.abs(y01 * x21 - y21 * x01) > epsilon3) || !r) {
      this._append`L${this._x1 = x12},${this._y1 = y12}`;
    } else {
      let x20 = x22 - x06, y20 = y22 - y06, l21_2 = x21 * x21 + y21 * y21, l20_2 = x20 * x20 + y20 * y20, l21 = Math.sqrt(l21_2), l01 = Math.sqrt(l01_2), l = r * Math.tan((pi3 - Math.acos((l21_2 + l01_2 - l20_2) / (2 * l21 * l01))) / 2), t01 = l / l01, t21 = l / l21;
      if (Math.abs(t01 - 1) > epsilon3) {
        this._append`L${x12 + t01 * x01},${y12 + t01 * y01}`;
      }
      this._append`A${r},${r},0,0,${+(y01 * x20 > x01 * y20)},${this._x1 = x12 + t21 * x21},${this._y1 = y12 + t21 * y21}`;
    }
  }
  arc(x3, y3, r, a0, a1, ccw) {
    x3 = +x3, y3 = +y3, r = +r, ccw = !!ccw;
    if (r < 0) throw new Error(`negative radius: ${r}`);
    let dx = r * Math.cos(a0), dy = r * Math.sin(a0), x06 = x3 + dx, y06 = y3 + dy, cw = 1 ^ ccw, da2 = ccw ? a0 - a1 : a1 - a0;
    if (this._x1 === null) {
      this._append`M${x06},${y06}`;
    } else if (Math.abs(this._x1 - x06) > epsilon3 || Math.abs(this._y1 - y06) > epsilon3) {
      this._append`L${x06},${y06}`;
    }
    if (!r) return;
    if (da2 < 0) da2 = da2 % tau3 + tau3;
    if (da2 > tauEpsilon) {
      this._append`A${r},${r},0,1,${cw},${x3 - dx},${y3 - dy}A${r},${r},0,1,${cw},${this._x1 = x06},${this._y1 = y06}`;
    } else if (da2 > epsilon3) {
      this._append`A${r},${r},0,${+(da2 >= pi3)},${cw},${this._x1 = x3 + r * Math.cos(a1)},${this._y1 = y3 + r * Math.sin(a1)}`;
    }
  }
  rect(x3, y3, w, h) {
    this._append`M${this._x0 = this._x1 = +x3},${this._y0 = this._y1 = +y3}h${w = +w}v${+h}h${-w}Z`;
  }
  toString() {
    return this._;
  }
};
function path() {
  return new Path();
}
path.prototype = Path.prototype;
function pathRound(digits = 3) {
  return new Path(+digits);
}

// node_modules/d3-chord/src/array.js
var slice2 = Array.prototype.slice;

// node_modules/d3-contour/src/array.js
var array3 = Array.prototype;
var slice3 = array3.slice;

// node_modules/d3-contour/src/ascending.js
function ascending_default(a2, b) {
  return a2 - b;
}

// node_modules/d3-contour/src/area.js
function area_default(ring) {
  var i = 0, n = ring.length, area2 = ring[n - 1][1] * ring[0][0] - ring[n - 1][0] * ring[0][1];
  while (++i < n) area2 += ring[i - 1][1] * ring[i][0] - ring[i - 1][0] * ring[i][1];
  return area2;
}

// node_modules/d3-contour/src/constant.js
var constant_default6 = (x3) => () => x3;

// node_modules/d3-contour/src/contains.js
function contains_default(ring, hole) {
  var i = -1, n = hole.length, c4;
  while (++i < n) if (c4 = ringContains(ring, hole[i])) return c4;
  return 0;
}
function ringContains(ring, point6) {
  var x3 = point6[0], y3 = point6[1], contains = -1;
  for (var i = 0, n = ring.length, j = n - 1; i < n; j = i++) {
    var pi7 = ring[i], xi = pi7[0], yi = pi7[1], pj = ring[j], xj = pj[0], yj = pj[1];
    if (segmentContains(pi7, pj, point6)) return 0;
    if (yi > y3 !== yj > y3 && x3 < (xj - xi) * (y3 - yi) / (yj - yi) + xi) contains = -contains;
  }
  return contains;
}
function segmentContains(a2, b, c4) {
  var i;
  return collinear(a2, b, c4) && within(a2[i = +(a2[0] === b[0])], c4[i], b[i]);
}
function collinear(a2, b, c4) {
  return (b[0] - a2[0]) * (c4[1] - a2[1]) === (c4[0] - a2[0]) * (b[1] - a2[1]);
}
function within(p, q, r) {
  return p <= q && q <= r || r <= q && q <= p;
}

// node_modules/d3-contour/src/noop.js
function noop_default() {
}

// node_modules/d3-contour/src/contours.js
var cases = [
  [],
  [[[1, 1.5], [0.5, 1]]],
  [[[1.5, 1], [1, 1.5]]],
  [[[1.5, 1], [0.5, 1]]],
  [[[1, 0.5], [1.5, 1]]],
  [[[1, 1.5], [0.5, 1]], [[1, 0.5], [1.5, 1]]],
  [[[1, 0.5], [1, 1.5]]],
  [[[1, 0.5], [0.5, 1]]],
  [[[0.5, 1], [1, 0.5]]],
  [[[1, 1.5], [1, 0.5]]],
  [[[0.5, 1], [1, 0.5]], [[1.5, 1], [1, 1.5]]],
  [[[1.5, 1], [1, 0.5]]],
  [[[0.5, 1], [1.5, 1]]],
  [[[1, 1.5], [1.5, 1]]],
  [[[0.5, 1], [1, 1.5]]],
  []
];
function contours_default() {
  var dx = 1, dy = 1, threshold2 = thresholdSturges, smooth = smoothLinear;
  function contours(values2) {
    var tz = threshold2(values2);
    if (!Array.isArray(tz)) {
      const e = extent(values2, finite);
      tz = ticks(...nice(e[0], e[1], tz), tz);
      while (tz[tz.length - 1] >= e[1]) tz.pop();
      while (tz[1] < e[0]) tz.shift();
    } else {
      tz = tz.slice().sort(ascending_default);
    }
    return tz.map((value) => contour2(values2, value));
  }
  function contour2(values2, value) {
    const v2 = value == null ? NaN : +value;
    if (isNaN(v2)) throw new Error(`invalid value: ${value}`);
    var polygons = [], holes = [];
    isorings(values2, v2, function(ring) {
      smooth(ring, values2, v2);
      if (area_default(ring) > 0) polygons.push([ring]);
      else holes.push(ring);
    });
    holes.forEach(function(hole) {
      for (var i = 0, n = polygons.length, polygon; i < n; ++i) {
        if (contains_default((polygon = polygons[i])[0], hole) !== -1) {
          polygon.push(hole);
          return;
        }
      }
    });
    return {
      type: "MultiPolygon",
      value,
      coordinates: polygons
    };
  }
  function isorings(values2, value, callback) {
    var fragmentByStart = new Array(), fragmentByEnd = new Array(), x3, y3, t03, t13, t22, t32;
    x3 = y3 = -1;
    t13 = above(values2[0], value);
    cases[t13 << 1].forEach(stitch);
    while (++x3 < dx - 1) {
      t03 = t13, t13 = above(values2[x3 + 1], value);
      cases[t03 | t13 << 1].forEach(stitch);
    }
    cases[t13 << 0].forEach(stitch);
    while (++y3 < dy - 1) {
      x3 = -1;
      t13 = above(values2[y3 * dx + dx], value);
      t22 = above(values2[y3 * dx], value);
      cases[t13 << 1 | t22 << 2].forEach(stitch);
      while (++x3 < dx - 1) {
        t03 = t13, t13 = above(values2[y3 * dx + dx + x3 + 1], value);
        t32 = t22, t22 = above(values2[y3 * dx + x3 + 1], value);
        cases[t03 | t13 << 1 | t22 << 2 | t32 << 3].forEach(stitch);
      }
      cases[t13 | t22 << 3].forEach(stitch);
    }
    x3 = -1;
    t22 = values2[y3 * dx] >= value;
    cases[t22 << 2].forEach(stitch);
    while (++x3 < dx - 1) {
      t32 = t22, t22 = above(values2[y3 * dx + x3 + 1], value);
      cases[t22 << 2 | t32 << 3].forEach(stitch);
    }
    cases[t22 << 3].forEach(stitch);
    function stitch(line2) {
      var start2 = [line2[0][0] + x3, line2[0][1] + y3], end = [line2[1][0] + x3, line2[1][1] + y3], startIndex = index2(start2), endIndex = index2(end), f, g;
      if (f = fragmentByEnd[startIndex]) {
        if (g = fragmentByStart[endIndex]) {
          delete fragmentByEnd[f.end];
          delete fragmentByStart[g.start];
          if (f === g) {
            f.ring.push(end);
            callback(f.ring);
          } else {
            fragmentByStart[f.start] = fragmentByEnd[g.end] = { start: f.start, end: g.end, ring: f.ring.concat(g.ring) };
          }
        } else {
          delete fragmentByEnd[f.end];
          f.ring.push(end);
          fragmentByEnd[f.end = endIndex] = f;
        }
      } else if (f = fragmentByStart[endIndex]) {
        if (g = fragmentByEnd[startIndex]) {
          delete fragmentByStart[f.start];
          delete fragmentByEnd[g.end];
          if (f === g) {
            f.ring.push(end);
            callback(f.ring);
          } else {
            fragmentByStart[g.start] = fragmentByEnd[f.end] = { start: g.start, end: f.end, ring: g.ring.concat(f.ring) };
          }
        } else {
          delete fragmentByStart[f.start];
          f.ring.unshift(start2);
          fragmentByStart[f.start = startIndex] = f;
        }
      } else {
        fragmentByStart[startIndex] = fragmentByEnd[endIndex] = { start: startIndex, end: endIndex, ring: [start2, end] };
      }
    }
  }
  function index2(point6) {
    return point6[0] * 2 + point6[1] * (dx + 1) * 4;
  }
  function smoothLinear(ring, values2, value) {
    ring.forEach(function(point6) {
      var x3 = point6[0], y3 = point6[1], xt = x3 | 0, yt = y3 | 0, v1 = valid(values2[yt * dx + xt]);
      if (x3 > 0 && x3 < dx && xt === x3) {
        point6[0] = smooth1(x3, valid(values2[yt * dx + xt - 1]), v1, value);
      }
      if (y3 > 0 && y3 < dy && yt === y3) {
        point6[1] = smooth1(y3, valid(values2[(yt - 1) * dx + xt]), v1, value);
      }
    });
  }
  contours.contour = contour2;
  contours.size = function(_) {
    if (!arguments.length) return [dx, dy];
    var _0 = Math.floor(_[0]), _1 = Math.floor(_[1]);
    if (!(_0 >= 0 && _1 >= 0)) throw new Error("invalid size");
    return dx = _0, dy = _1, contours;
  };
  contours.thresholds = function(_) {
    return arguments.length ? (threshold2 = typeof _ === "function" ? _ : Array.isArray(_) ? constant_default6(slice3.call(_)) : constant_default6(_), contours) : threshold2;
  };
  contours.smooth = function(_) {
    return arguments.length ? (smooth = _ ? smoothLinear : noop_default, contours) : smooth === smoothLinear;
  };
  return contours;
}
function finite(x3) {
  return isFinite(x3) ? x3 : NaN;
}
function above(x3, value) {
  return x3 == null ? false : +x3 >= value;
}
function valid(v2) {
  return v2 == null || isNaN(v2 = +v2) ? -Infinity : v2;
}
function smooth1(x3, v0, v1, value) {
  const a2 = value - v0;
  const b = v1 - v0;
  const d = isFinite(a2) || isFinite(b) ? a2 / b : Math.sign(a2) / Math.sign(b);
  return isNaN(d) ? x3 : x3 + d - 0.5;
}

// node_modules/d3-contour/src/density.js
function defaultX(d) {
  return d[0];
}
function defaultY(d) {
  return d[1];
}
function defaultWeight() {
  return 1;
}
function density_default() {
  var x3 = defaultX, y3 = defaultY, weight = defaultWeight, dx = 960, dy = 500, r = 20, k2 = 2, o = r * 3, n = dx + o * 2 >> k2, m = dy + o * 2 >> k2, threshold2 = constant_default6(20);
  function grid(data) {
    var values2 = new Float32Array(n * m), pow2k = Math.pow(2, -k2), i = -1;
    for (const d of data) {
      var xi = (x3(d, ++i, data) + o) * pow2k, yi = (y3(d, i, data) + o) * pow2k, wi = +weight(d, i, data);
      if (wi && xi >= 0 && xi < n && yi >= 0 && yi < m) {
        var x06 = Math.floor(xi), y06 = Math.floor(yi), xt = xi - x06 - 0.5, yt = yi - y06 - 0.5;
        values2[x06 + y06 * n] += (1 - xt) * (1 - yt) * wi;
        values2[x06 + 1 + y06 * n] += xt * (1 - yt) * wi;
        values2[x06 + 1 + (y06 + 1) * n] += xt * yt * wi;
        values2[x06 + (y06 + 1) * n] += (1 - xt) * yt * wi;
      }
    }
    blur2({ data: values2, width: n, height: m }, r * pow2k);
    return values2;
  }
  function density2(data) {
    var values2 = grid(data), tz = threshold2(values2), pow4k = Math.pow(2, 2 * k2);
    if (!Array.isArray(tz)) {
      tz = ticks(Number.MIN_VALUE, max(values2) / pow4k, tz);
    }
    return contours_default().size([n, m]).thresholds(tz.map((d) => d * pow4k))(values2).map((c4, i) => (c4.value = +tz[i], transform2(c4)));
  }
  density2.contours = function(data) {
    var values2 = grid(data), contours = contours_default().size([n, m]), pow4k = Math.pow(2, 2 * k2), contour2 = (value) => {
      value = +value;
      var c4 = transform2(contours.contour(values2, value * pow4k));
      c4.value = value;
      return c4;
    };
    Object.defineProperty(contour2, "max", { get: () => max(values2) / pow4k });
    return contour2;
  };
  function transform2(geometry) {
    geometry.coordinates.forEach(transformPolygon);
    return geometry;
  }
  function transformPolygon(coordinates) {
    coordinates.forEach(transformRing);
  }
  function transformRing(coordinates) {
    coordinates.forEach(transformPoint);
  }
  function transformPoint(coordinates) {
    coordinates[0] = coordinates[0] * Math.pow(2, k2) - o;
    coordinates[1] = coordinates[1] * Math.pow(2, k2) - o;
  }
  function resize() {
    o = r * 3;
    n = dx + o * 2 >> k2;
    m = dy + o * 2 >> k2;
    return density2;
  }
  density2.x = function(_) {
    return arguments.length ? (x3 = typeof _ === "function" ? _ : constant_default6(+_), density2) : x3;
  };
  density2.y = function(_) {
    return arguments.length ? (y3 = typeof _ === "function" ? _ : constant_default6(+_), density2) : y3;
  };
  density2.weight = function(_) {
    return arguments.length ? (weight = typeof _ === "function" ? _ : constant_default6(+_), density2) : weight;
  };
  density2.size = function(_) {
    if (!arguments.length) return [dx, dy];
    var _0 = +_[0], _1 = +_[1];
    if (!(_0 >= 0 && _1 >= 0)) throw new Error("invalid size");
    return dx = _0, dy = _1, resize();
  };
  density2.cellSize = function(_) {
    if (!arguments.length) return 1 << k2;
    if (!((_ = +_) >= 1)) throw new Error("invalid cell size");
    return k2 = Math.floor(Math.log(_) / Math.LN2), resize();
  };
  density2.thresholds = function(_) {
    return arguments.length ? (threshold2 = typeof _ === "function" ? _ : Array.isArray(_) ? constant_default6(slice3.call(_)) : constant_default6(_), density2) : threshold2;
  };
  density2.bandwidth = function(_) {
    if (!arguments.length) return Math.sqrt(r * (r + 1));
    if (!((_ = +_) >= 0)) throw new Error("invalid bandwidth");
    return r = (Math.sqrt(4 * _ * _ + 1) - 1) / 2, resize();
  };
  return density2;
}

// node_modules/robust-predicates/esm/util.js
var epsilon5 = 11102230246251565e-32;
var splitter = 134217729;
var resulterrbound = (3 + 8 * epsilon5) * epsilon5;
function sum2(elen, e, flen, f, h) {
  let Q, Qnew, hh, bvirt;
  let enow = e[0];
  let fnow = f[0];
  let eindex = 0;
  let findex = 0;
  if (fnow > enow === fnow > -enow) {
    Q = enow;
    enow = e[++eindex];
  } else {
    Q = fnow;
    fnow = f[++findex];
  }
  let hindex = 0;
  if (eindex < elen && findex < flen) {
    if (fnow > enow === fnow > -enow) {
      Qnew = enow + Q;
      hh = Q - (Qnew - enow);
      enow = e[++eindex];
    } else {
      Qnew = fnow + Q;
      hh = Q - (Qnew - fnow);
      fnow = f[++findex];
    }
    Q = Qnew;
    if (hh !== 0) {
      h[hindex++] = hh;
    }
    while (eindex < elen && findex < flen) {
      if (fnow > enow === fnow > -enow) {
        Qnew = Q + enow;
        bvirt = Qnew - Q;
        hh = Q - (Qnew - bvirt) + (enow - bvirt);
        enow = e[++eindex];
      } else {
        Qnew = Q + fnow;
        bvirt = Qnew - Q;
        hh = Q - (Qnew - bvirt) + (fnow - bvirt);
        fnow = f[++findex];
      }
      Q = Qnew;
      if (hh !== 0) {
        h[hindex++] = hh;
      }
    }
  }
  while (eindex < elen) {
    Qnew = Q + enow;
    bvirt = Qnew - Q;
    hh = Q - (Qnew - bvirt) + (enow - bvirt);
    enow = e[++eindex];
    Q = Qnew;
    if (hh !== 0) {
      h[hindex++] = hh;
    }
  }
  while (findex < flen) {
    Qnew = Q + fnow;
    bvirt = Qnew - Q;
    hh = Q - (Qnew - bvirt) + (fnow - bvirt);
    fnow = f[++findex];
    Q = Qnew;
    if (hh !== 0) {
      h[hindex++] = hh;
    }
  }
  if (Q !== 0 || hindex === 0) {
    h[hindex++] = Q;
  }
  return hindex;
}
function estimate(elen, e) {
  let Q = e[0];
  for (let i = 1; i < elen; i++) Q += e[i];
  return Q;
}
function vec(n) {
  return new Float64Array(n);
}

// node_modules/robust-predicates/esm/orient2d.js
var ccwerrboundA = (3 + 16 * epsilon5) * epsilon5;
var ccwerrboundB = (2 + 12 * epsilon5) * epsilon5;
var ccwerrboundC = (9 + 64 * epsilon5) * epsilon5 * epsilon5;
var B2 = vec(4);
var C1 = vec(8);
var C2 = vec(12);
var D2 = vec(16);
var u = vec(4);
function orient2dadapt(ax, ay, bx, by, cx, cy, detsum) {
  let acxtail, acytail, bcxtail, bcytail;
  let bvirt, c4, ahi, alo, bhi, blo, _i, _j, _0, s1, s0, t13, t03, u32;
  const acx = ax - cx;
  const bcx = bx - cx;
  const acy = ay - cy;
  const bcy = by - cy;
  s1 = acx * bcy;
  c4 = splitter * acx;
  ahi = c4 - (c4 - acx);
  alo = acx - ahi;
  c4 = splitter * bcy;
  bhi = c4 - (c4 - bcy);
  blo = bcy - bhi;
  s0 = alo * blo - (s1 - ahi * bhi - alo * bhi - ahi * blo);
  t13 = acy * bcx;
  c4 = splitter * acy;
  ahi = c4 - (c4 - acy);
  alo = acy - ahi;
  c4 = splitter * bcx;
  bhi = c4 - (c4 - bcx);
  blo = bcx - bhi;
  t03 = alo * blo - (t13 - ahi * bhi - alo * bhi - ahi * blo);
  _i = s0 - t03;
  bvirt = s0 - _i;
  B2[0] = s0 - (_i + bvirt) + (bvirt - t03);
  _j = s1 + _i;
  bvirt = _j - s1;
  _0 = s1 - (_j - bvirt) + (_i - bvirt);
  _i = _0 - t13;
  bvirt = _0 - _i;
  B2[1] = _0 - (_i + bvirt) + (bvirt - t13);
  u32 = _j + _i;
  bvirt = u32 - _j;
  B2[2] = _j - (u32 - bvirt) + (_i - bvirt);
  B2[3] = u32;
  let det = estimate(4, B2);
  let errbound = ccwerrboundB * detsum;
  if (det >= errbound || -det >= errbound) {
    return det;
  }
  bvirt = ax - acx;
  acxtail = ax - (acx + bvirt) + (bvirt - cx);
  bvirt = bx - bcx;
  bcxtail = bx - (bcx + bvirt) + (bvirt - cx);
  bvirt = ay - acy;
  acytail = ay - (acy + bvirt) + (bvirt - cy);
  bvirt = by - bcy;
  bcytail = by - (bcy + bvirt) + (bvirt - cy);
  if (acxtail === 0 && acytail === 0 && bcxtail === 0 && bcytail === 0) {
    return det;
  }
  errbound = ccwerrboundC * detsum + resulterrbound * Math.abs(det);
  det += acx * bcytail + bcy * acxtail - (acy * bcxtail + bcx * acytail);
  if (det >= errbound || -det >= errbound) return det;
  s1 = acxtail * bcy;
  c4 = splitter * acxtail;
  ahi = c4 - (c4 - acxtail);
  alo = acxtail - ahi;
  c4 = splitter * bcy;
  bhi = c4 - (c4 - bcy);
  blo = bcy - bhi;
  s0 = alo * blo - (s1 - ahi * bhi - alo * bhi - ahi * blo);
  t13 = acytail * bcx;
  c4 = splitter * acytail;
  ahi = c4 - (c4 - acytail);
  alo = acytail - ahi;
  c4 = splitter * bcx;
  bhi = c4 - (c4 - bcx);
  blo = bcx - bhi;
  t03 = alo * blo - (t13 - ahi * bhi - alo * bhi - ahi * blo);
  _i = s0 - t03;
  bvirt = s0 - _i;
  u[0] = s0 - (_i + bvirt) + (bvirt - t03);
  _j = s1 + _i;
  bvirt = _j - s1;
  _0 = s1 - (_j - bvirt) + (_i - bvirt);
  _i = _0 - t13;
  bvirt = _0 - _i;
  u[1] = _0 - (_i + bvirt) + (bvirt - t13);
  u32 = _j + _i;
  bvirt = u32 - _j;
  u[2] = _j - (u32 - bvirt) + (_i - bvirt);
  u[3] = u32;
  const C1len = sum2(4, B2, 4, u, C1);
  s1 = acx * bcytail;
  c4 = splitter * acx;
  ahi = c4 - (c4 - acx);
  alo = acx - ahi;
  c4 = splitter * bcytail;
  bhi = c4 - (c4 - bcytail);
  blo = bcytail - bhi;
  s0 = alo * blo - (s1 - ahi * bhi - alo * bhi - ahi * blo);
  t13 = acy * bcxtail;
  c4 = splitter * acy;
  ahi = c4 - (c4 - acy);
  alo = acy - ahi;
  c4 = splitter * bcxtail;
  bhi = c4 - (c4 - bcxtail);
  blo = bcxtail - bhi;
  t03 = alo * blo - (t13 - ahi * bhi - alo * bhi - ahi * blo);
  _i = s0 - t03;
  bvirt = s0 - _i;
  u[0] = s0 - (_i + bvirt) + (bvirt - t03);
  _j = s1 + _i;
  bvirt = _j - s1;
  _0 = s1 - (_j - bvirt) + (_i - bvirt);
  _i = _0 - t13;
  bvirt = _0 - _i;
  u[1] = _0 - (_i + bvirt) + (bvirt - t13);
  u32 = _j + _i;
  bvirt = u32 - _j;
  u[2] = _j - (u32 - bvirt) + (_i - bvirt);
  u[3] = u32;
  const C2len = sum2(C1len, C1, 4, u, C2);
  s1 = acxtail * bcytail;
  c4 = splitter * acxtail;
  ahi = c4 - (c4 - acxtail);
  alo = acxtail - ahi;
  c4 = splitter * bcytail;
  bhi = c4 - (c4 - bcytail);
  blo = bcytail - bhi;
  s0 = alo * blo - (s1 - ahi * bhi - alo * bhi - ahi * blo);
  t13 = acytail * bcxtail;
  c4 = splitter * acytail;
  ahi = c4 - (c4 - acytail);
  alo = acytail - ahi;
  c4 = splitter * bcxtail;
  bhi = c4 - (c4 - bcxtail);
  blo = bcxtail - bhi;
  t03 = alo * blo - (t13 - ahi * bhi - alo * bhi - ahi * blo);
  _i = s0 - t03;
  bvirt = s0 - _i;
  u[0] = s0 - (_i + bvirt) + (bvirt - t03);
  _j = s1 + _i;
  bvirt = _j - s1;
  _0 = s1 - (_j - bvirt) + (_i - bvirt);
  _i = _0 - t13;
  bvirt = _0 - _i;
  u[1] = _0 - (_i + bvirt) + (bvirt - t13);
  u32 = _j + _i;
  bvirt = u32 - _j;
  u[2] = _j - (u32 - bvirt) + (_i - bvirt);
  u[3] = u32;
  const Dlen = sum2(C2len, C2, 4, u, D2);
  return D2[Dlen - 1];
}
function orient2d(ax, ay, bx, by, cx, cy) {
  const detleft = (ay - cy) * (bx - cx);
  const detright = (ax - cx) * (by - cy);
  const det = detleft - detright;
  const detsum = Math.abs(detleft + detright);
  if (Math.abs(det) >= ccwerrboundA * detsum) return det;
  return -orient2dadapt(ax, ay, bx, by, cx, cy, detsum);
}

// node_modules/robust-predicates/esm/orient3d.js
var o3derrboundA = (7 + 56 * epsilon5) * epsilon5;
var o3derrboundB = (3 + 28 * epsilon5) * epsilon5;
var o3derrboundC = (26 + 288 * epsilon5) * epsilon5 * epsilon5;
var bc = vec(4);
var ca = vec(4);
var ab = vec(4);
var at_b = vec(4);
var at_c = vec(4);
var bt_c = vec(4);
var bt_a = vec(4);
var ct_a = vec(4);
var ct_b = vec(4);
var bct = vec(8);
var cat = vec(8);
var abt = vec(8);
var u2 = vec(4);
var _8 = vec(8);
var _8b = vec(8);
var _16 = vec(16);
var _12 = vec(12);
var fin = vec(192);
var fin2 = vec(192);

// node_modules/robust-predicates/esm/incircle.js
var iccerrboundA = (10 + 96 * epsilon5) * epsilon5;
var iccerrboundB = (4 + 48 * epsilon5) * epsilon5;
var iccerrboundC = (44 + 576 * epsilon5) * epsilon5 * epsilon5;
var bc2 = vec(4);
var ca2 = vec(4);
var ab2 = vec(4);
var aa = vec(4);
var bb = vec(4);
var cc = vec(4);
var u3 = vec(4);
var v = vec(4);
var axtbc = vec(8);
var aytbc = vec(8);
var bxtca = vec(8);
var bytca = vec(8);
var cxtab = vec(8);
var cytab = vec(8);
var abt2 = vec(8);
var bct2 = vec(8);
var cat2 = vec(8);
var abtt = vec(4);
var bctt = vec(4);
var catt = vec(4);
var _82 = vec(8);
var _162 = vec(16);
var _16b = vec(16);
var _16c = vec(16);
var _32 = vec(32);
var _32b = vec(32);
var _48 = vec(48);
var _64 = vec(64);
var fin3 = vec(1152);
var fin22 = vec(1152);

// node_modules/robust-predicates/esm/insphere.js
var isperrboundA = (16 + 224 * epsilon5) * epsilon5;
var isperrboundB = (5 + 72 * epsilon5) * epsilon5;
var isperrboundC = (71 + 1408 * epsilon5) * epsilon5 * epsilon5;
var ab3 = vec(4);
var bc3 = vec(4);
var cd = vec(4);
var de = vec(4);
var ea = vec(4);
var ac = vec(4);
var bd = vec(4);
var ce = vec(4);
var da = vec(4);
var eb = vec(4);
var abc = vec(24);
var bcd = vec(24);
var cde = vec(24);
var dea = vec(24);
var eab = vec(24);
var abd = vec(24);
var bce = vec(24);
var cda = vec(24);
var deb = vec(24);
var eac = vec(24);
var adet = vec(1152);
var bdet = vec(1152);
var cdet = vec(1152);
var ddet = vec(1152);
var edet = vec(1152);
var abdet = vec(2304);
var cddet = vec(2304);
var cdedet = vec(3456);
var deter = vec(5760);
var _83 = vec(8);
var _8b2 = vec(8);
var _8c = vec(8);
var _163 = vec(16);
var _24 = vec(24);
var _482 = vec(48);
var _48b = vec(48);
var _96 = vec(96);
var _192 = vec(192);
var _384x = vec(384);
var _384y = vec(384);
var _384z = vec(384);
var _768 = vec(768);
var xdet = vec(96);
var ydet = vec(96);
var zdet = vec(96);
var fin4 = vec(1152);

// node_modules/delaunator/index.js
var EPSILON = Math.pow(2, -52);
var EDGE_STACK = new Uint32Array(512);
var Delaunator = class _Delaunator {
  /**
   * Constructs a delaunay triangulation object given an array of points (`[x, y]` by default).
   * `getX` and `getY` are optional functions of the form `(point) => value` for custom point formats.
   *
   * @template P
   * @param {P[]} points
   * @param {(p: P) => number} [getX]
   * @param {(p: P) => number} [getY]
   */
  // @ts-expect-error TS2322
  static from(points, getX = defaultGetX, getY = defaultGetY) {
    const n = points.length;
    const coords = new Float64Array(n * 2);
    for (let i = 0; i < n; i++) {
      const p = points[i];
      coords[2 * i] = getX(p);
      coords[2 * i + 1] = getY(p);
    }
    return new _Delaunator(coords);
  }
  /**
   * Constructs a delaunay triangulation object given an array of point coordinates of the form:
   * `[x0, y0, x1, y1, ...]` (use a typed array for best performance). Duplicate points are skipped.
   *
   * @param {T} coords
   */
  constructor(coords) {
    const n = coords.length >> 1;
    if (n > 0 && typeof coords[0] !== "number") throw new Error("Expected coords to contain numbers.");
    this.coords = coords;
    const maxTriangles = Math.max(2 * n - 5, 0);
    this._triangles = new Uint32Array(maxTriangles * 3);
    this._halfedges = new Int32Array(maxTriangles * 3);
    this._hashSize = Math.ceil(Math.sqrt(n));
    this._hullPrev = new Uint32Array(n);
    this._hullNext = new Uint32Array(n);
    this._hullTri = new Uint32Array(n);
    this._hullHash = new Int32Array(this._hashSize);
    this._ids = new Uint32Array(n);
    this._dists = new Float64Array(n);
    this.trianglesLen = 0;
    this._cx = 0;
    this._cy = 0;
    this._hullStart = 0;
    this.hull = this._triangles;
    this.triangles = this._triangles;
    this.halfedges = this._halfedges;
    this.update();
  }
  /**
   * Updates the triangulation if you modified `delaunay.coords` values in place, avoiding expensive memory allocations.
   * Useful for iterative relaxation algorithms such as Lloyd's.
   */
  update() {
    const { coords, _hullPrev: hullPrev, _hullNext: hullNext, _hullTri: hullTri, _hullHash: hullHash } = this;
    const n = coords.length >> 1;
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY2 = -Infinity;
    for (let i = 0; i < n; i++) {
      const x3 = coords[2 * i];
      const y3 = coords[2 * i + 1];
      if (x3 < minX) minX = x3;
      if (y3 < minY) minY = y3;
      if (x3 > maxX) maxX = x3;
      if (y3 > maxY2) maxY2 = y3;
      this._ids[i] = i;
    }
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY2) / 2;
    let i0 = 0, i1 = 0, i2 = 0;
    for (let i = 0, minDist = Infinity; i < n; i++) {
      const d = dist(cx, cy, coords[2 * i], coords[2 * i + 1]);
      if (d < minDist) {
        i0 = i;
        minDist = d;
      }
    }
    const i0x = coords[2 * i0];
    const i0y = coords[2 * i0 + 1];
    for (let i = 0, minDist = Infinity; i < n; i++) {
      if (i === i0) continue;
      const d = dist(i0x, i0y, coords[2 * i], coords[2 * i + 1]);
      if (d < minDist && d > 0) {
        i1 = i;
        minDist = d;
      }
    }
    let i1x = coords[2 * i1];
    let i1y = coords[2 * i1 + 1];
    let minRadius = Infinity;
    for (let i = 0; i < n; i++) {
      if (i === i0 || i === i1) continue;
      const r = circumradius(i0x, i0y, i1x, i1y, coords[2 * i], coords[2 * i + 1]);
      if (r < minRadius) {
        i2 = i;
        minRadius = r;
      }
    }
    let i2x = coords[2 * i2];
    let i2y = coords[2 * i2 + 1];
    if (minRadius === Infinity) {
      for (let i = 0; i < n; i++) {
        this._dists[i] = coords[2 * i] - coords[0] || coords[2 * i + 1] - coords[1];
      }
      quicksort(this._ids, this._dists, 0, n - 1);
      const hull2 = new Uint32Array(n);
      let j = 0;
      for (let i = 0, d0 = -Infinity; i < n; i++) {
        const id2 = this._ids[i];
        const d = this._dists[id2];
        if (d > d0) {
          hull2[j++] = id2;
          d0 = d;
        }
      }
      this.hull = hull2.subarray(0, j);
      this.triangles = new Uint32Array(0);
      this.halfedges = new Int32Array(0);
      return;
    }
    if (orient2d(i0x, i0y, i1x, i1y, i2x, i2y) < 0) {
      const i = i1;
      const x3 = i1x;
      const y3 = i1y;
      i1 = i2;
      i1x = i2x;
      i1y = i2y;
      i2 = i;
      i2x = x3;
      i2y = y3;
    }
    const center2 = circumcenter(i0x, i0y, i1x, i1y, i2x, i2y);
    this._cx = center2.x;
    this._cy = center2.y;
    for (let i = 0; i < n; i++) {
      this._dists[i] = dist(coords[2 * i], coords[2 * i + 1], center2.x, center2.y);
    }
    quicksort(this._ids, this._dists, 0, n - 1);
    this._hullStart = i0;
    let hullSize = 3;
    hullNext[i0] = hullPrev[i2] = i1;
    hullNext[i1] = hullPrev[i0] = i2;
    hullNext[i2] = hullPrev[i1] = i0;
    hullTri[i0] = 0;
    hullTri[i1] = 1;
    hullTri[i2] = 2;
    hullHash.fill(-1);
    hullHash[this._hashKey(i0x, i0y)] = i0;
    hullHash[this._hashKey(i1x, i1y)] = i1;
    hullHash[this._hashKey(i2x, i2y)] = i2;
    this.trianglesLen = 0;
    this._addTriangle(i0, i1, i2, -1, -1, -1);
    for (let k2 = 0, xp = 0, yp = 0; k2 < this._ids.length; k2++) {
      const i = this._ids[k2];
      const x3 = coords[2 * i];
      const y3 = coords[2 * i + 1];
      if (k2 > 0 && Math.abs(x3 - xp) <= EPSILON && Math.abs(y3 - yp) <= EPSILON) continue;
      xp = x3;
      yp = y3;
      if (i === i0 || i === i1 || i === i2) continue;
      let start2 = 0;
      for (let j = 0, key = this._hashKey(x3, y3); j < this._hashSize; j++) {
        start2 = hullHash[(key + j) % this._hashSize];
        if (start2 !== -1 && start2 !== hullNext[start2]) break;
      }
      start2 = hullPrev[start2];
      let e = start2, q;
      while (q = hullNext[e], orient2d(x3, y3, coords[2 * e], coords[2 * e + 1], coords[2 * q], coords[2 * q + 1]) >= 0) {
        e = q;
        if (e === start2) {
          e = -1;
          break;
        }
      }
      if (e === -1) continue;
      let t = this._addTriangle(e, i, hullNext[e], -1, -1, hullTri[e]);
      hullTri[i] = this._legalize(t + 2);
      hullTri[e] = t;
      hullSize++;
      let n2 = hullNext[e];
      while (q = hullNext[n2], orient2d(x3, y3, coords[2 * n2], coords[2 * n2 + 1], coords[2 * q], coords[2 * q + 1]) < 0) {
        t = this._addTriangle(n2, i, q, hullTri[i], -1, hullTri[n2]);
        hullTri[i] = this._legalize(t + 2);
        hullNext[n2] = n2;
        hullSize--;
        n2 = q;
      }
      if (e === start2) {
        while (q = hullPrev[e], orient2d(x3, y3, coords[2 * q], coords[2 * q + 1], coords[2 * e], coords[2 * e + 1]) < 0) {
          t = this._addTriangle(q, i, e, -1, hullTri[e], hullTri[q]);
          this._legalize(t + 2);
          hullTri[q] = t;
          hullNext[e] = e;
          hullSize--;
          e = q;
        }
      }
      this._hullStart = hullPrev[i] = e;
      hullNext[e] = hullPrev[n2] = i;
      hullNext[i] = n2;
      hullHash[this._hashKey(x3, y3)] = i;
      hullHash[this._hashKey(coords[2 * e], coords[2 * e + 1])] = e;
    }
    this.hull = new Uint32Array(hullSize);
    for (let i = 0, e = this._hullStart; i < hullSize; i++) {
      this.hull[i] = e;
      e = hullNext[e];
    }
    this.triangles = this._triangles.subarray(0, this.trianglesLen);
    this.halfedges = this._halfedges.subarray(0, this.trianglesLen);
  }
  /**
   * Calculate an angle-based key for the edge hash used for advancing convex hull.
   *
   * @param {number} x
   * @param {number} y
   * @private
   */
  _hashKey(x3, y3) {
    return Math.floor(pseudoAngle(x3 - this._cx, y3 - this._cy) * this._hashSize) % this._hashSize;
  }
  /**
   * Flip an edge in a pair of triangles if it doesn't satisfy the Delaunay condition.
   *
   * @param {number} a
   * @private
   */
  _legalize(a2) {
    const { _triangles: triangles, _halfedges: halfedges, coords } = this;
    let i = 0;
    let ar = 0;
    while (true) {
      const b = halfedges[a2];
      const a0 = a2 - a2 % 3;
      ar = a0 + (a2 + 2) % 3;
      if (b === -1) {
        if (i === 0) break;
        a2 = EDGE_STACK[--i];
        continue;
      }
      const b02 = b - b % 3;
      const al = a0 + (a2 + 1) % 3;
      const bl = b02 + (b + 2) % 3;
      const p0 = triangles[ar];
      const pr = triangles[a2];
      const pl = triangles[al];
      const p1 = triangles[bl];
      const illegal = inCircle(
        coords[2 * p0],
        coords[2 * p0 + 1],
        coords[2 * pr],
        coords[2 * pr + 1],
        coords[2 * pl],
        coords[2 * pl + 1],
        coords[2 * p1],
        coords[2 * p1 + 1]
      );
      if (illegal) {
        triangles[a2] = p1;
        triangles[b] = p0;
        const hbl = halfedges[bl];
        if (hbl === -1) {
          let e = this._hullStart;
          do {
            if (this._hullTri[e] === bl) {
              this._hullTri[e] = a2;
              break;
            }
            e = this._hullPrev[e];
          } while (e !== this._hullStart);
        }
        this._link(a2, hbl);
        this._link(b, halfedges[ar]);
        this._link(ar, bl);
        const br = b02 + (b + 1) % 3;
        if (i < EDGE_STACK.length) {
          EDGE_STACK[i++] = br;
        }
      } else {
        if (i === 0) break;
        a2 = EDGE_STACK[--i];
      }
    }
    return ar;
  }
  /**
   * Link two half-edges to each other.
   * @param {number} a
   * @param {number} b
   * @private
   */
  _link(a2, b) {
    this._halfedges[a2] = b;
    if (b !== -1) this._halfedges[b] = a2;
  }
  /**
   * Add a new triangle given vertex indices and adjacent half-edge ids.
   *
   * @param {number} i0
   * @param {number} i1
   * @param {number} i2
   * @param {number} a
   * @param {number} b
   * @param {number} c
   * @private
   */
  _addTriangle(i0, i1, i2, a2, b, c4) {
    const t = this.trianglesLen;
    this._triangles[t] = i0;
    this._triangles[t + 1] = i1;
    this._triangles[t + 2] = i2;
    this._link(t, a2);
    this._link(t + 1, b);
    this._link(t + 2, c4);
    this.trianglesLen += 3;
    return t;
  }
};
function pseudoAngle(dx, dy) {
  const p = dx / (Math.abs(dx) + Math.abs(dy));
  return (dy > 0 ? 3 - p : 1 + p) / 4;
}
function dist(ax, ay, bx, by) {
  const dx = ax - bx;
  const dy = ay - by;
  return dx * dx + dy * dy;
}
function inCircle(ax, ay, bx, by, cx, cy, px, py) {
  const dx = ax - px;
  const dy = ay - py;
  const ex = bx - px;
  const ey = by - py;
  const fx = cx - px;
  const fy = cy - py;
  const ap = dx * dx + dy * dy;
  const bp = ex * ex + ey * ey;
  const cp = fx * fx + fy * fy;
  return dx * (ey * cp - bp * fy) - dy * (ex * cp - bp * fx) + ap * (ex * fy - ey * fx) < 0;
}
function circumradius(ax, ay, bx, by, cx, cy) {
  const dx = bx - ax;
  const dy = by - ay;
  const ex = cx - ax;
  const ey = cy - ay;
  const bl = dx * dx + dy * dy;
  const cl = ex * ex + ey * ey;
  const d = 0.5 / (dx * ey - dy * ex);
  const x3 = (ey * bl - dy * cl) * d;
  const y3 = (dx * cl - ex * bl) * d;
  return x3 * x3 + y3 * y3;
}
function circumcenter(ax, ay, bx, by, cx, cy) {
  const dx = bx - ax;
  const dy = by - ay;
  const ex = cx - ax;
  const ey = cy - ay;
  const bl = dx * dx + dy * dy;
  const cl = ex * ex + ey * ey;
  const d = 0.5 / (dx * ey - dy * ex);
  const x3 = ax + (ey * bl - dy * cl) * d;
  const y3 = ay + (dx * cl - ex * bl) * d;
  return { x: x3, y: y3 };
}
function quicksort(ids, dists, left2, right2) {
  if (right2 - left2 <= 20) {
    for (let i = left2 + 1; i <= right2; i++) {
      const temp = ids[i];
      const tempDist = dists[temp];
      let j = i - 1;
      while (j >= left2 && dists[ids[j]] > tempDist) ids[j + 1] = ids[j--];
      ids[j + 1] = temp;
    }
  } else {
    const median2 = left2 + right2 >> 1;
    let i = left2 + 1;
    let j = right2;
    swap2(ids, median2, i);
    if (dists[ids[left2]] > dists[ids[right2]]) swap2(ids, left2, right2);
    if (dists[ids[i]] > dists[ids[right2]]) swap2(ids, i, right2);
    if (dists[ids[left2]] > dists[ids[i]]) swap2(ids, left2, i);
    const temp = ids[i];
    const tempDist = dists[temp];
    while (true) {
      do
        i++;
      while (dists[ids[i]] < tempDist);
      do
        j--;
      while (dists[ids[j]] > tempDist);
      if (j < i) break;
      swap2(ids, i, j);
    }
    ids[left2 + 1] = ids[j];
    ids[j] = temp;
    if (right2 - i + 1 >= j - left2) {
      quicksort(ids, dists, i, right2);
      quicksort(ids, dists, left2, j - 1);
    } else {
      quicksort(ids, dists, left2, j - 1);
      quicksort(ids, dists, i, right2);
    }
  }
}
function swap2(arr, i, j) {
  const tmp = arr[i];
  arr[i] = arr[j];
  arr[j] = tmp;
}
function defaultGetX(p) {
  return p[0];
}
function defaultGetY(p) {
  return p[1];
}

// node_modules/d3-delaunay/src/path.js
var epsilon6 = 1e-6;
var Path2 = class {
  constructor() {
    this._x0 = this._y0 = // start of current subpath
    this._x1 = this._y1 = null;
    this._ = "";
  }
  moveTo(x3, y3) {
    this._ += `M${this._x0 = this._x1 = +x3},${this._y0 = this._y1 = +y3}`;
  }
  closePath() {
    if (this._x1 !== null) {
      this._x1 = this._x0, this._y1 = this._y0;
      this._ += "Z";
    }
  }
  lineTo(x3, y3) {
    this._ += `L${this._x1 = +x3},${this._y1 = +y3}`;
  }
  arc(x3, y3, r) {
    x3 = +x3, y3 = +y3, r = +r;
    const x06 = x3 + r;
    const y06 = y3;
    if (r < 0) throw new Error("negative radius");
    if (this._x1 === null) this._ += `M${x06},${y06}`;
    else if (Math.abs(this._x1 - x06) > epsilon6 || Math.abs(this._y1 - y06) > epsilon6) this._ += "L" + x06 + "," + y06;
    if (!r) return;
    this._ += `A${r},${r},0,1,1,${x3 - r},${y3}A${r},${r},0,1,1,${this._x1 = x06},${this._y1 = y06}`;
  }
  rect(x3, y3, w, h) {
    this._ += `M${this._x0 = this._x1 = +x3},${this._y0 = this._y1 = +y3}h${+w}v${+h}h${-w}Z`;
  }
  value() {
    return this._ || null;
  }
};

// node_modules/d3-delaunay/src/polygon.js
var Polygon = class {
  constructor() {
    this._ = [];
  }
  moveTo(x3, y3) {
    this._.push([x3, y3]);
  }
  closePath() {
    this._.push(this._[0].slice());
  }
  lineTo(x3, y3) {
    this._.push([x3, y3]);
  }
  value() {
    return this._.length ? this._ : null;
  }
};

// node_modules/d3-delaunay/src/voronoi.js
var Voronoi = class {
  constructor(delaunay, [xmin, ymin, xmax, ymax] = [0, 0, 960, 500]) {
    if (!((xmax = +xmax) >= (xmin = +xmin)) || !((ymax = +ymax) >= (ymin = +ymin))) throw new Error("invalid bounds");
    this.delaunay = delaunay;
    this._circumcenters = new Float64Array(delaunay.points.length * 2);
    this.vectors = new Float64Array(delaunay.points.length * 2);
    this.xmax = xmax, this.xmin = xmin;
    this.ymax = ymax, this.ymin = ymin;
    this._init();
  }
  update() {
    this.delaunay.update();
    this._init();
    return this;
  }
  _init() {
    const { delaunay: { points, hull: hull2, triangles }, vectors } = this;
    let bx, by;
    const circumcenters = this.circumcenters = this._circumcenters.subarray(0, triangles.length / 3 * 2);
    for (let i = 0, j = 0, n = triangles.length, x3, y3; i < n; i += 3, j += 2) {
      const t13 = triangles[i] * 2;
      const t22 = triangles[i + 1] * 2;
      const t32 = triangles[i + 2] * 2;
      const x13 = points[t13];
      const y13 = points[t13 + 1];
      const x22 = points[t22];
      const y22 = points[t22 + 1];
      const x32 = points[t32];
      const y32 = points[t32 + 1];
      const dx = x22 - x13;
      const dy = y22 - y13;
      const ex = x32 - x13;
      const ey = y32 - y13;
      const ab4 = (dx * ey - dy * ex) * 2;
      if (Math.abs(ab4) < 1e-9) {
        if (bx === void 0) {
          bx = by = 0;
          for (const i2 of hull2) bx += points[i2 * 2], by += points[i2 * 2 + 1];
          bx /= hull2.length, by /= hull2.length;
        }
        const a2 = 1e9 * Math.sign((bx - x13) * ey - (by - y13) * ex);
        x3 = (x13 + x32) / 2 - a2 * ey;
        y3 = (y13 + y32) / 2 + a2 * ex;
      } else {
        const d = 1 / ab4;
        const bl = dx * dx + dy * dy;
        const cl = ex * ex + ey * ey;
        x3 = x13 + (ey * bl - dy * cl) * d;
        y3 = y13 + (dx * cl - ex * bl) * d;
      }
      circumcenters[j] = x3;
      circumcenters[j + 1] = y3;
    }
    let h = hull2[hull2.length - 1];
    let p0, p1 = h * 4;
    let x06, x12 = points[2 * h];
    let y06, y12 = points[2 * h + 1];
    vectors.fill(0);
    for (let i = 0; i < hull2.length; ++i) {
      h = hull2[i];
      p0 = p1, x06 = x12, y06 = y12;
      p1 = h * 4, x12 = points[2 * h], y12 = points[2 * h + 1];
      vectors[p0 + 2] = vectors[p1] = y06 - y12;
      vectors[p0 + 3] = vectors[p1 + 1] = x12 - x06;
    }
  }
  render(context) {
    const buffer = context == null ? context = new Path2() : void 0;
    const { delaunay: { halfedges, inedges, hull: hull2 }, circumcenters, vectors } = this;
    if (hull2.length <= 1) return null;
    for (let i = 0, n = halfedges.length; i < n; ++i) {
      const j = halfedges[i];
      if (j < i) continue;
      const ti = Math.floor(i / 3) * 2;
      const tj = Math.floor(j / 3) * 2;
      const xi = circumcenters[ti];
      const yi = circumcenters[ti + 1];
      const xj = circumcenters[tj];
      const yj = circumcenters[tj + 1];
      this._renderSegment(xi, yi, xj, yj, context);
    }
    let h0, h1 = hull2[hull2.length - 1];
    for (let i = 0; i < hull2.length; ++i) {
      h0 = h1, h1 = hull2[i];
      const t = Math.floor(inedges[h1] / 3) * 2;
      const x3 = circumcenters[t];
      const y3 = circumcenters[t + 1];
      const v2 = h0 * 4;
      const p = this._project(x3, y3, vectors[v2 + 2], vectors[v2 + 3]);
      if (p) this._renderSegment(x3, y3, p[0], p[1], context);
    }
    return buffer && buffer.value();
  }
  renderBounds(context) {
    const buffer = context == null ? context = new Path2() : void 0;
    context.rect(this.xmin, this.ymin, this.xmax - this.xmin, this.ymax - this.ymin);
    return buffer && buffer.value();
  }
  renderCell(i, context) {
    const buffer = context == null ? context = new Path2() : void 0;
    const points = this._clip(i);
    if (points === null || !points.length) return;
    context.moveTo(points[0], points[1]);
    let n = points.length;
    while (points[0] === points[n - 2] && points[1] === points[n - 1] && n > 1) n -= 2;
    for (let i2 = 2; i2 < n; i2 += 2) {
      if (points[i2] !== points[i2 - 2] || points[i2 + 1] !== points[i2 - 1])
        context.lineTo(points[i2], points[i2 + 1]);
    }
    context.closePath();
    return buffer && buffer.value();
  }
  *cellPolygons() {
    const { delaunay: { points } } = this;
    for (let i = 0, n = points.length / 2; i < n; ++i) {
      const cell2 = this.cellPolygon(i);
      if (cell2) cell2.index = i, yield cell2;
    }
  }
  cellPolygon(i) {
    const polygon = new Polygon();
    this.renderCell(i, polygon);
    return polygon.value();
  }
  _renderSegment(x06, y06, x12, y12, context) {
    let S;
    const c0 = this._regioncode(x06, y06);
    const c1 = this._regioncode(x12, y12);
    if (c0 === 0 && c1 === 0) {
      context.moveTo(x06, y06);
      context.lineTo(x12, y12);
    } else if (S = this._clipSegment(x06, y06, x12, y12, c0, c1)) {
      context.moveTo(S[0], S[1]);
      context.lineTo(S[2], S[3]);
    }
  }
  contains(i, x3, y3) {
    if ((x3 = +x3, x3 !== x3) || (y3 = +y3, y3 !== y3)) return false;
    return this.delaunay._step(i, x3, y3) === i;
  }
  *neighbors(i) {
    const ci = this._clip(i);
    if (ci) for (const j of this.delaunay.neighbors(i)) {
      const cj = this._clip(j);
      if (cj) loop: for (let ai = 0, li = ci.length; ai < li; ai += 2) {
        for (let aj = 0, lj = cj.length; aj < lj; aj += 2) {
          if (ci[ai] === cj[aj] && ci[ai + 1] === cj[aj + 1] && ci[(ai + 2) % li] === cj[(aj + lj - 2) % lj] && ci[(ai + 3) % li] === cj[(aj + lj - 1) % lj]) {
            yield j;
            break loop;
          }
        }
      }
    }
  }
  _cell(i) {
    const { circumcenters, delaunay: { inedges, halfedges, triangles } } = this;
    const e0 = inedges[i];
    if (e0 === -1) return null;
    const points = [];
    let e = e0;
    do {
      const t = Math.floor(e / 3);
      points.push(circumcenters[t * 2], circumcenters[t * 2 + 1]);
      e = e % 3 === 2 ? e - 2 : e + 1;
      if (triangles[e] !== i) break;
      e = halfedges[e];
    } while (e !== e0 && e !== -1);
    return points;
  }
  _clip(i) {
    if (i === 0 && this.delaunay.hull.length === 1) {
      return [this.xmax, this.ymin, this.xmax, this.ymax, this.xmin, this.ymax, this.xmin, this.ymin];
    }
    const points = this._cell(i);
    if (points === null) return null;
    const { vectors: V } = this;
    const v2 = i * 4;
    return this._simplify(V[v2] || V[v2 + 1] ? this._clipInfinite(i, points, V[v2], V[v2 + 1], V[v2 + 2], V[v2 + 3]) : this._clipFinite(i, points));
  }
  _clipFinite(i, points) {
    const n = points.length;
    let P = null;
    let x06, y06, x12 = points[n - 2], y12 = points[n - 1];
    let c0, c1 = this._regioncode(x12, y12);
    let e0, e1 = 0;
    for (let j = 0; j < n; j += 2) {
      x06 = x12, y06 = y12, x12 = points[j], y12 = points[j + 1];
      c0 = c1, c1 = this._regioncode(x12, y12);
      if (c0 === 0 && c1 === 0) {
        e0 = e1, e1 = 0;
        if (P) P.push(x12, y12);
        else P = [x12, y12];
      } else {
        let S, sx0, sy0, sx1, sy1;
        if (c0 === 0) {
          if ((S = this._clipSegment(x06, y06, x12, y12, c0, c1)) === null) continue;
          [sx0, sy0, sx1, sy1] = S;
        } else {
          if ((S = this._clipSegment(x12, y12, x06, y06, c1, c0)) === null) continue;
          [sx1, sy1, sx0, sy0] = S;
          e0 = e1, e1 = this._edgecode(sx0, sy0);
          if (e0 && e1) this._edge(i, e0, e1, P, P.length);
          if (P) P.push(sx0, sy0);
          else P = [sx0, sy0];
        }
        e0 = e1, e1 = this._edgecode(sx1, sy1);
        if (e0 && e1) this._edge(i, e0, e1, P, P.length);
        if (P) P.push(sx1, sy1);
        else P = [sx1, sy1];
      }
    }
    if (P) {
      e0 = e1, e1 = this._edgecode(P[0], P[1]);
      if (e0 && e1) this._edge(i, e0, e1, P, P.length);
    } else if (this.contains(i, (this.xmin + this.xmax) / 2, (this.ymin + this.ymax) / 2)) {
      return [this.xmax, this.ymin, this.xmax, this.ymax, this.xmin, this.ymax, this.xmin, this.ymin];
    }
    return P;
  }
  _clipSegment(x06, y06, x12, y12, c0, c1) {
    const flip2 = c0 < c1;
    if (flip2) [x06, y06, x12, y12, c0, c1] = [x12, y12, x06, y06, c1, c0];
    while (true) {
      if (c0 === 0 && c1 === 0) return flip2 ? [x12, y12, x06, y06] : [x06, y06, x12, y12];
      if (c0 & c1) return null;
      let x3, y3, c4 = c0 || c1;
      if (c4 & 8) x3 = x06 + (x12 - x06) * (this.ymax - y06) / (y12 - y06), y3 = this.ymax;
      else if (c4 & 4) x3 = x06 + (x12 - x06) * (this.ymin - y06) / (y12 - y06), y3 = this.ymin;
      else if (c4 & 2) y3 = y06 + (y12 - y06) * (this.xmax - x06) / (x12 - x06), x3 = this.xmax;
      else y3 = y06 + (y12 - y06) * (this.xmin - x06) / (x12 - x06), x3 = this.xmin;
      if (c0) x06 = x3, y06 = y3, c0 = this._regioncode(x06, y06);
      else x12 = x3, y12 = y3, c1 = this._regioncode(x12, y12);
    }
  }
  _clipInfinite(i, points, vx0, vy0, vxn, vyn) {
    let P = Array.from(points), p;
    if (p = this._project(P[0], P[1], vx0, vy0)) P.unshift(p[0], p[1]);
    if (p = this._project(P[P.length - 2], P[P.length - 1], vxn, vyn)) P.push(p[0], p[1]);
    if (P = this._clipFinite(i, P)) {
      for (let j = 0, n = P.length, c0, c1 = this._edgecode(P[n - 2], P[n - 1]); j < n; j += 2) {
        c0 = c1, c1 = this._edgecode(P[j], P[j + 1]);
        if (c0 && c1) j = this._edge(i, c0, c1, P, j), n = P.length;
      }
    } else if (this.contains(i, (this.xmin + this.xmax) / 2, (this.ymin + this.ymax) / 2)) {
      P = [this.xmin, this.ymin, this.xmax, this.ymin, this.xmax, this.ymax, this.xmin, this.ymax];
    }
    return P;
  }
  _edge(i, e0, e1, P, j) {
    while (e0 !== e1) {
      let x3, y3;
      switch (e0) {
        case 5:
          e0 = 4;
          continue;
        // top-left
        case 4:
          e0 = 6, x3 = this.xmax, y3 = this.ymin;
          break;
        // top
        case 6:
          e0 = 2;
          continue;
        // top-right
        case 2:
          e0 = 10, x3 = this.xmax, y3 = this.ymax;
          break;
        // right
        case 10:
          e0 = 8;
          continue;
        // bottom-right
        case 8:
          e0 = 9, x3 = this.xmin, y3 = this.ymax;
          break;
        // bottom
        case 9:
          e0 = 1;
          continue;
        // bottom-left
        case 1:
          e0 = 5, x3 = this.xmin, y3 = this.ymin;
          break;
      }
      if ((P[j] !== x3 || P[j + 1] !== y3) && this.contains(i, x3, y3)) {
        P.splice(j, 0, x3, y3), j += 2;
      }
    }
    return j;
  }
  _project(x06, y06, vx, vy) {
    let t = Infinity, c4, x3, y3;
    if (vy < 0) {
      if (y06 <= this.ymin) return null;
      if ((c4 = (this.ymin - y06) / vy) < t) y3 = this.ymin, x3 = x06 + (t = c4) * vx;
    } else if (vy > 0) {
      if (y06 >= this.ymax) return null;
      if ((c4 = (this.ymax - y06) / vy) < t) y3 = this.ymax, x3 = x06 + (t = c4) * vx;
    }
    if (vx > 0) {
      if (x06 >= this.xmax) return null;
      if ((c4 = (this.xmax - x06) / vx) < t) x3 = this.xmax, y3 = y06 + (t = c4) * vy;
    } else if (vx < 0) {
      if (x06 <= this.xmin) return null;
      if ((c4 = (this.xmin - x06) / vx) < t) x3 = this.xmin, y3 = y06 + (t = c4) * vy;
    }
    return [x3, y3];
  }
  _edgecode(x3, y3) {
    return (x3 === this.xmin ? 1 : x3 === this.xmax ? 2 : 0) | (y3 === this.ymin ? 4 : y3 === this.ymax ? 8 : 0);
  }
  _regioncode(x3, y3) {
    return (x3 < this.xmin ? 1 : x3 > this.xmax ? 2 : 0) | (y3 < this.ymin ? 4 : y3 > this.ymax ? 8 : 0);
  }
  _simplify(P) {
    if (P && P.length > 4) {
      for (let i = 0; i < P.length; i += 2) {
        const j = (i + 2) % P.length, k2 = (i + 4) % P.length;
        if (P[i] === P[j] && P[j] === P[k2] || P[i + 1] === P[j + 1] && P[j + 1] === P[k2 + 1]) {
          P.splice(j, 2), i -= 2;
        }
      }
      if (!P.length) P = null;
    }
    return P;
  }
};

// node_modules/d3-delaunay/src/delaunay.js
var tau4 = 2 * Math.PI;
var pow = Math.pow;
function pointX(p) {
  return p[0];
}
function pointY(p) {
  return p[1];
}
function collinear2(d) {
  const { triangles, coords } = d;
  for (let i = 0; i < triangles.length; i += 3) {
    const a2 = 2 * triangles[i], b = 2 * triangles[i + 1], c4 = 2 * triangles[i + 2], cross3 = (coords[c4] - coords[a2]) * (coords[b + 1] - coords[a2 + 1]) - (coords[b] - coords[a2]) * (coords[c4 + 1] - coords[a2 + 1]);
    if (cross3 > 1e-10) return false;
  }
  return true;
}
function jitter(x3, y3, r) {
  return [x3 + Math.sin(x3 + y3) * r, y3 + Math.cos(x3 - y3) * r];
}
var Delaunay = class _Delaunay {
  static from(points, fx = pointX, fy = pointY, that) {
    return new _Delaunay("length" in points ? flatArray(points, fx, fy, that) : Float64Array.from(flatIterable(points, fx, fy, that)));
  }
  constructor(points) {
    this._delaunator = new Delaunator(points);
    this.inedges = new Int32Array(points.length / 2);
    this._hullIndex = new Int32Array(points.length / 2);
    this.points = this._delaunator.coords;
    this._init();
  }
  update() {
    this._delaunator.update();
    this._init();
    return this;
  }
  _init() {
    const d = this._delaunator, points = this.points;
    if (d.hull && d.hull.length > 2 && collinear2(d)) {
      this.collinear = Int32Array.from({ length: points.length / 2 }, (_, i) => i).sort((i, j) => points[2 * i] - points[2 * j] || points[2 * i + 1] - points[2 * j + 1]);
      const e = this.collinear[0], f = this.collinear[this.collinear.length - 1], bounds = [points[2 * e], points[2 * e + 1], points[2 * f], points[2 * f + 1]], r = 1e-8 * Math.hypot(bounds[3] - bounds[1], bounds[2] - bounds[0]);
      for (let i = 0, n = points.length / 2; i < n; ++i) {
        const p = jitter(points[2 * i], points[2 * i + 1], r);
        points[2 * i] = p[0];
        points[2 * i + 1] = p[1];
      }
      this._delaunator = new Delaunator(points);
    } else {
      delete this.collinear;
    }
    const halfedges = this.halfedges = this._delaunator.halfedges;
    const hull2 = this.hull = this._delaunator.hull;
    const triangles = this.triangles = this._delaunator.triangles;
    const inedges = this.inedges.fill(-1);
    const hullIndex = this._hullIndex.fill(-1);
    for (let e = 0, n = halfedges.length; e < n; ++e) {
      const p = triangles[e % 3 === 2 ? e - 2 : e + 1];
      if (halfedges[e] === -1 || inedges[p] === -1) inedges[p] = e;
    }
    for (let i = 0, n = hull2.length; i < n; ++i) {
      hullIndex[hull2[i]] = i;
    }
    if (hull2.length <= 2 && hull2.length > 0) {
      this.triangles = new Int32Array(3).fill(-1);
      this.halfedges = new Int32Array(3).fill(-1);
      this.triangles[0] = hull2[0];
      inedges[hull2[0]] = 1;
      if (hull2.length === 2) {
        inedges[hull2[1]] = 0;
        this.triangles[1] = hull2[1];
        this.triangles[2] = hull2[1];
      }
    }
  }
  voronoi(bounds) {
    return new Voronoi(this, bounds);
  }
  *neighbors(i) {
    const { inedges, hull: hull2, _hullIndex, halfedges, triangles, collinear: collinear3 } = this;
    if (collinear3) {
      const l = collinear3.indexOf(i);
      if (l > 0) yield collinear3[l - 1];
      if (l < collinear3.length - 1) yield collinear3[l + 1];
      return;
    }
    const e0 = inedges[i];
    if (e0 === -1) return;
    let e = e0, p0 = -1;
    do {
      yield p0 = triangles[e];
      e = e % 3 === 2 ? e - 2 : e + 1;
      if (triangles[e] !== i) return;
      e = halfedges[e];
      if (e === -1) {
        const p = hull2[(_hullIndex[i] + 1) % hull2.length];
        if (p !== p0) yield p;
        return;
      }
    } while (e !== e0);
  }
  find(x3, y3, i = 0) {
    if ((x3 = +x3, x3 !== x3) || (y3 = +y3, y3 !== y3)) return -1;
    const i0 = i;
    let c4;
    while ((c4 = this._step(i, x3, y3)) >= 0 && c4 !== i && c4 !== i0) i = c4;
    return c4;
  }
  _step(i, x3, y3) {
    const { inedges, hull: hull2, _hullIndex, halfedges, triangles, points } = this;
    if (inedges[i] === -1 || !points.length) return (i + 1) % (points.length >> 1);
    let c4 = i;
    let dc = pow(x3 - points[i * 2], 2) + pow(y3 - points[i * 2 + 1], 2);
    const e0 = inedges[i];
    let e = e0;
    do {
      let t = triangles[e];
      const dt = pow(x3 - points[t * 2], 2) + pow(y3 - points[t * 2 + 1], 2);
      if (dt < dc) dc = dt, c4 = t;
      e = e % 3 === 2 ? e - 2 : e + 1;
      if (triangles[e] !== i) break;
      e = halfedges[e];
      if (e === -1) {
        e = hull2[(_hullIndex[i] + 1) % hull2.length];
        if (e !== t) {
          if (pow(x3 - points[e * 2], 2) + pow(y3 - points[e * 2 + 1], 2) < dc) return e;
        }
        break;
      }
    } while (e !== e0);
    return c4;
  }
  render(context) {
    const buffer = context == null ? context = new Path2() : void 0;
    const { points, halfedges, triangles } = this;
    for (let i = 0, n = halfedges.length; i < n; ++i) {
      const j = halfedges[i];
      if (j < i) continue;
      const ti = triangles[i] * 2;
      const tj = triangles[j] * 2;
      context.moveTo(points[ti], points[ti + 1]);
      context.lineTo(points[tj], points[tj + 1]);
    }
    this.renderHull(context);
    return buffer && buffer.value();
  }
  renderPoints(context, r) {
    if (r === void 0 && (!context || typeof context.moveTo !== "function")) r = context, context = null;
    r = r == void 0 ? 2 : +r;
    const buffer = context == null ? context = new Path2() : void 0;
    const { points } = this;
    for (let i = 0, n = points.length; i < n; i += 2) {
      const x3 = points[i], y3 = points[i + 1];
      context.moveTo(x3 + r, y3);
      context.arc(x3, y3, r, 0, tau4);
    }
    return buffer && buffer.value();
  }
  renderHull(context) {
    const buffer = context == null ? context = new Path2() : void 0;
    const { hull: hull2, points } = this;
    const h = hull2[0] * 2, n = hull2.length;
    context.moveTo(points[h], points[h + 1]);
    for (let i = 1; i < n; ++i) {
      const h2 = 2 * hull2[i];
      context.lineTo(points[h2], points[h2 + 1]);
    }
    context.closePath();
    return buffer && buffer.value();
  }
  hullPolygon() {
    const polygon = new Polygon();
    this.renderHull(polygon);
    return polygon.value();
  }
  renderTriangle(i, context) {
    const buffer = context == null ? context = new Path2() : void 0;
    const { points, triangles } = this;
    const t03 = triangles[i *= 3] * 2;
    const t13 = triangles[i + 1] * 2;
    const t22 = triangles[i + 2] * 2;
    context.moveTo(points[t03], points[t03 + 1]);
    context.lineTo(points[t13], points[t13 + 1]);
    context.lineTo(points[t22], points[t22 + 1]);
    context.closePath();
    return buffer && buffer.value();
  }
  *trianglePolygons() {
    const { triangles } = this;
    for (let i = 0, n = triangles.length / 3; i < n; ++i) {
      yield this.trianglePolygon(i);
    }
  }
  trianglePolygon(i) {
    const polygon = new Polygon();
    this.renderTriangle(i, polygon);
    return polygon.value();
  }
};
function flatArray(points, fx, fy, that) {
  const n = points.length;
  const array4 = new Float64Array(n * 2);
  for (let i = 0; i < n; ++i) {
    const p = points[i];
    array4[i * 2] = fx.call(that, p, i, points);
    array4[i * 2 + 1] = fy.call(that, p, i, points);
  }
  return array4;
}
function* flatIterable(points, fx, fy, that) {
  let i = 0;
  for (const p of points) {
    yield fx.call(that, p, i, points);
    yield fy.call(that, p, i, points);
    ++i;
  }
}

// node_modules/d3-dsv/src/dsv.js
var EOL = {};
var EOF = {};
var QUOTE = 34;
var NEWLINE = 10;
var RETURN = 13;
function objectConverter(columns) {
  return new Function("d", "return {" + columns.map(function(name, i) {
    return JSON.stringify(name) + ": d[" + i + '] || ""';
  }).join(",") + "}");
}
function customConverter(columns, f) {
  var object = objectConverter(columns);
  return function(row, i) {
    return f(object(row), i, columns);
  };
}
function inferColumns(rows) {
  var columnSet = /* @__PURE__ */ Object.create(null), columns = [];
  rows.forEach(function(row) {
    for (var column2 in row) {
      if (!(column2 in columnSet)) {
        columns.push(columnSet[column2] = column2);
      }
    }
  });
  return columns;
}
function pad(value, width) {
  var s2 = value + "", length3 = s2.length;
  return length3 < width ? new Array(width - length3 + 1).join(0) + s2 : s2;
}
function formatYear(year) {
  return year < 0 ? "-" + pad(-year, 6) : year > 9999 ? "+" + pad(year, 6) : pad(year, 4);
}
function formatDate(date2) {
  var hours = date2.getUTCHours(), minutes = date2.getUTCMinutes(), seconds2 = date2.getUTCSeconds(), milliseconds2 = date2.getUTCMilliseconds();
  return isNaN(date2) ? "Invalid Date" : formatYear(date2.getUTCFullYear(), 4) + "-" + pad(date2.getUTCMonth() + 1, 2) + "-" + pad(date2.getUTCDate(), 2) + (milliseconds2 ? "T" + pad(hours, 2) + ":" + pad(minutes, 2) + ":" + pad(seconds2, 2) + "." + pad(milliseconds2, 3) + "Z" : seconds2 ? "T" + pad(hours, 2) + ":" + pad(minutes, 2) + ":" + pad(seconds2, 2) + "Z" : minutes || hours ? "T" + pad(hours, 2) + ":" + pad(minutes, 2) + "Z" : "");
}
function dsv_default(delimiter) {
  var reFormat = new RegExp('["' + delimiter + "\n\r]"), DELIMITER = delimiter.charCodeAt(0);
  function parse2(text2, f) {
    var convert, columns, rows = parseRows(text2, function(row, i) {
      if (convert) return convert(row, i - 1);
      columns = row, convert = f ? customConverter(row, f) : objectConverter(row);
    });
    rows.columns = columns || [];
    return rows;
  }
  function parseRows(text2, f) {
    var rows = [], N = text2.length, I = 0, n = 0, t, eof = N <= 0, eol = false;
    if (text2.charCodeAt(N - 1) === NEWLINE) --N;
    if (text2.charCodeAt(N - 1) === RETURN) --N;
    function token() {
      if (eof) return EOF;
      if (eol) return eol = false, EOL;
      var i, j = I, c4;
      if (text2.charCodeAt(j) === QUOTE) {
        while (I++ < N && text2.charCodeAt(I) !== QUOTE || text2.charCodeAt(++I) === QUOTE) ;
        if ((i = I) >= N) eof = true;
        else if ((c4 = text2.charCodeAt(I++)) === NEWLINE) eol = true;
        else if (c4 === RETURN) {
          eol = true;
          if (text2.charCodeAt(I) === NEWLINE) ++I;
        }
        return text2.slice(j + 1, i - 1).replace(/""/g, '"');
      }
      while (I < N) {
        if ((c4 = text2.charCodeAt(i = I++)) === NEWLINE) eol = true;
        else if (c4 === RETURN) {
          eol = true;
          if (text2.charCodeAt(I) === NEWLINE) ++I;
        } else if (c4 !== DELIMITER) continue;
        return text2.slice(j, i);
      }
      return eof = true, text2.slice(j, N);
    }
    while ((t = token()) !== EOF) {
      var row = [];
      while (t !== EOL && t !== EOF) row.push(t), t = token();
      if (f && (row = f(row, n++)) == null) continue;
      rows.push(row);
    }
    return rows;
  }
  function preformatBody(rows, columns) {
    return rows.map(function(row) {
      return columns.map(function(column2) {
        return formatValue(row[column2]);
      }).join(delimiter);
    });
  }
  function format3(rows, columns) {
    if (columns == null) columns = inferColumns(rows);
    return [columns.map(formatValue).join(delimiter)].concat(preformatBody(rows, columns)).join("\n");
  }
  function formatBody(rows, columns) {
    if (columns == null) columns = inferColumns(rows);
    return preformatBody(rows, columns).join("\n");
  }
  function formatRows(rows) {
    return rows.map(formatRow).join("\n");
  }
  function formatRow(row) {
    return row.map(formatValue).join(delimiter);
  }
  function formatValue(value) {
    return value == null ? "" : value instanceof Date ? formatDate(value) : reFormat.test(value += "") ? '"' + value.replace(/"/g, '""') + '"' : value;
  }
  return {
    parse: parse2,
    parseRows,
    format: format3,
    formatBody,
    formatRows,
    formatRow,
    formatValue
  };
}

// node_modules/d3-dsv/src/csv.js
var csv = dsv_default(",");
var csvParse = csv.parse;
var csvParseRows = csv.parseRows;
var csvFormat = csv.format;
var csvFormatBody = csv.formatBody;
var csvFormatRows = csv.formatRows;
var csvFormatRow = csv.formatRow;
var csvFormatValue = csv.formatValue;

// node_modules/d3-dsv/src/tsv.js
var tsv = dsv_default("	");
var tsvParse = tsv.parse;
var tsvParseRows = tsv.parseRows;
var tsvFormat = tsv.format;
var tsvFormatBody = tsv.formatBody;
var tsvFormatRows = tsv.formatRows;
var tsvFormatRow = tsv.formatRow;
var tsvFormatValue = tsv.formatValue;

// node_modules/d3-dsv/src/autoType.js
var fixtz = (/* @__PURE__ */ new Date("2019-01-01T00:00")).getHours() || (/* @__PURE__ */ new Date("2019-07-01T00:00")).getHours();

// node_modules/d3-fetch/src/text.js
function responseText(response) {
  if (!response.ok) throw new Error(response.status + " " + response.statusText);
  return response.text();
}
function text_default3(input, init2) {
  return fetch(input, init2).then(responseText);
}

// node_modules/d3-fetch/src/dsv.js
function dsvParse(parse2) {
  return function(input, init2, row) {
    if (arguments.length === 2 && typeof init2 === "function") row = init2, init2 = void 0;
    return text_default3(input, init2).then(function(response) {
      return parse2(response, row);
    });
  };
}
var csv2 = dsvParse(csvParse);
var tsv2 = dsvParse(tsvParse);

// node_modules/d3-fetch/src/xml.js
function parser(type2) {
  return (input, init2) => text_default3(input, init2).then((text2) => new DOMParser().parseFromString(text2, type2));
}
var xml_default = parser("application/xml");
var html = parser("text/html");
var svg = parser("image/svg+xml");

// node_modules/d3-quadtree/src/add.js
function add_default(d) {
  const x3 = +this._x.call(null, d), y3 = +this._y.call(null, d);
  return add(this.cover(x3, y3), x3, y3, d);
}
function add(tree2, x3, y3, d) {
  if (isNaN(x3) || isNaN(y3)) return tree2;
  var parent, node = tree2._root, leaf = { data: d }, x06 = tree2._x0, y06 = tree2._y0, x12 = tree2._x1, y12 = tree2._y1, xm, ym, xp, yp, right2, bottom2, i, j;
  if (!node) return tree2._root = leaf, tree2;
  while (node.length) {
    if (right2 = x3 >= (xm = (x06 + x12) / 2)) x06 = xm;
    else x12 = xm;
    if (bottom2 = y3 >= (ym = (y06 + y12) / 2)) y06 = ym;
    else y12 = ym;
    if (parent = node, !(node = node[i = bottom2 << 1 | right2])) return parent[i] = leaf, tree2;
  }
  xp = +tree2._x.call(null, node.data);
  yp = +tree2._y.call(null, node.data);
  if (x3 === xp && y3 === yp) return leaf.next = node, parent ? parent[i] = leaf : tree2._root = leaf, tree2;
  do {
    parent = parent ? parent[i] = new Array(4) : tree2._root = new Array(4);
    if (right2 = x3 >= (xm = (x06 + x12) / 2)) x06 = xm;
    else x12 = xm;
    if (bottom2 = y3 >= (ym = (y06 + y12) / 2)) y06 = ym;
    else y12 = ym;
  } while ((i = bottom2 << 1 | right2) === (j = (yp >= ym) << 1 | xp >= xm));
  return parent[j] = node, parent[i] = leaf, tree2;
}
function addAll(data) {
  var d, i, n = data.length, x3, y3, xz = new Array(n), yz = new Array(n), x06 = Infinity, y06 = Infinity, x12 = -Infinity, y12 = -Infinity;
  for (i = 0; i < n; ++i) {
    if (isNaN(x3 = +this._x.call(null, d = data[i])) || isNaN(y3 = +this._y.call(null, d))) continue;
    xz[i] = x3;
    yz[i] = y3;
    if (x3 < x06) x06 = x3;
    if (x3 > x12) x12 = x3;
    if (y3 < y06) y06 = y3;
    if (y3 > y12) y12 = y3;
  }
  if (x06 > x12 || y06 > y12) return this;
  this.cover(x06, y06).cover(x12, y12);
  for (i = 0; i < n; ++i) {
    add(this, xz[i], yz[i], data[i]);
  }
  return this;
}

// node_modules/d3-quadtree/src/cover.js
function cover_default(x3, y3) {
  if (isNaN(x3 = +x3) || isNaN(y3 = +y3)) return this;
  var x06 = this._x0, y06 = this._y0, x12 = this._x1, y12 = this._y1;
  if (isNaN(x06)) {
    x12 = (x06 = Math.floor(x3)) + 1;
    y12 = (y06 = Math.floor(y3)) + 1;
  } else {
    var z = x12 - x06 || 1, node = this._root, parent, i;
    while (x06 > x3 || x3 >= x12 || y06 > y3 || y3 >= y12) {
      i = (y3 < y06) << 1 | x3 < x06;
      parent = new Array(4), parent[i] = node, node = parent, z *= 2;
      switch (i) {
        case 0:
          x12 = x06 + z, y12 = y06 + z;
          break;
        case 1:
          x06 = x12 - z, y12 = y06 + z;
          break;
        case 2:
          x12 = x06 + z, y06 = y12 - z;
          break;
        case 3:
          x06 = x12 - z, y06 = y12 - z;
          break;
      }
    }
    if (this._root && this._root.length) this._root = node;
  }
  this._x0 = x06;
  this._y0 = y06;
  this._x1 = x12;
  this._y1 = y12;
  return this;
}

// node_modules/d3-quadtree/src/data.js
function data_default2() {
  var data = [];
  this.visit(function(node) {
    if (!node.length) do
      data.push(node.data);
    while (node = node.next);
  });
  return data;
}

// node_modules/d3-quadtree/src/extent.js
function extent_default(_) {
  return arguments.length ? this.cover(+_[0][0], +_[0][1]).cover(+_[1][0], +_[1][1]) : isNaN(this._x0) ? void 0 : [[this._x0, this._y0], [this._x1, this._y1]];
}

// node_modules/d3-quadtree/src/quad.js
function quad_default(node, x06, y06, x12, y12) {
  this.node = node;
  this.x0 = x06;
  this.y0 = y06;
  this.x1 = x12;
  this.y1 = y12;
}

// node_modules/d3-quadtree/src/find.js
function find_default(x3, y3, radius2) {
  var data, x06 = this._x0, y06 = this._y0, x12, y12, x22, y22, x32 = this._x1, y32 = this._y1, quads = [], node = this._root, q, i;
  if (node) quads.push(new quad_default(node, x06, y06, x32, y32));
  if (radius2 == null) radius2 = Infinity;
  else {
    x06 = x3 - radius2, y06 = y3 - radius2;
    x32 = x3 + radius2, y32 = y3 + radius2;
    radius2 *= radius2;
  }
  while (q = quads.pop()) {
    if (!(node = q.node) || (x12 = q.x0) > x32 || (y12 = q.y0) > y32 || (x22 = q.x1) < x06 || (y22 = q.y1) < y06) continue;
    if (node.length) {
      var xm = (x12 + x22) / 2, ym = (y12 + y22) / 2;
      quads.push(
        new quad_default(node[3], xm, ym, x22, y22),
        new quad_default(node[2], x12, ym, xm, y22),
        new quad_default(node[1], xm, y12, x22, ym),
        new quad_default(node[0], x12, y12, xm, ym)
      );
      if (i = (y3 >= ym) << 1 | x3 >= xm) {
        q = quads[quads.length - 1];
        quads[quads.length - 1] = quads[quads.length - 1 - i];
        quads[quads.length - 1 - i] = q;
      }
    } else {
      var dx = x3 - +this._x.call(null, node.data), dy = y3 - +this._y.call(null, node.data), d2 = dx * dx + dy * dy;
      if (d2 < radius2) {
        var d = Math.sqrt(radius2 = d2);
        x06 = x3 - d, y06 = y3 - d;
        x32 = x3 + d, y32 = y3 + d;
        data = node.data;
      }
    }
  }
  return data;
}

// node_modules/d3-quadtree/src/remove.js
function remove_default3(d) {
  if (isNaN(x3 = +this._x.call(null, d)) || isNaN(y3 = +this._y.call(null, d))) return this;
  var parent, node = this._root, retainer, previous, next, x06 = this._x0, y06 = this._y0, x12 = this._x1, y12 = this._y1, x3, y3, xm, ym, right2, bottom2, i, j;
  if (!node) return this;
  if (node.length) while (true) {
    if (right2 = x3 >= (xm = (x06 + x12) / 2)) x06 = xm;
    else x12 = xm;
    if (bottom2 = y3 >= (ym = (y06 + y12) / 2)) y06 = ym;
    else y12 = ym;
    if (!(parent = node, node = node[i = bottom2 << 1 | right2])) return this;
    if (!node.length) break;
    if (parent[i + 1 & 3] || parent[i + 2 & 3] || parent[i + 3 & 3]) retainer = parent, j = i;
  }
  while (node.data !== d) if (!(previous = node, node = node.next)) return this;
  if (next = node.next) delete node.next;
  if (previous) return next ? previous.next = next : delete previous.next, this;
  if (!parent) return this._root = next, this;
  next ? parent[i] = next : delete parent[i];
  if ((node = parent[0] || parent[1] || parent[2] || parent[3]) && node === (parent[3] || parent[2] || parent[1] || parent[0]) && !node.length) {
    if (retainer) retainer[j] = node;
    else this._root = node;
  }
  return this;
}
function removeAll(data) {
  for (var i = 0, n = data.length; i < n; ++i) this.remove(data[i]);
  return this;
}

// node_modules/d3-quadtree/src/root.js
function root_default() {
  return this._root;
}

// node_modules/d3-quadtree/src/size.js
function size_default2() {
  var size = 0;
  this.visit(function(node) {
    if (!node.length) do
      ++size;
    while (node = node.next);
  });
  return size;
}

// node_modules/d3-quadtree/src/visit.js
function visit_default(callback) {
  var quads = [], q, node = this._root, child, x06, y06, x12, y12;
  if (node) quads.push(new quad_default(node, this._x0, this._y0, this._x1, this._y1));
  while (q = quads.pop()) {
    if (!callback(node = q.node, x06 = q.x0, y06 = q.y0, x12 = q.x1, y12 = q.y1) && node.length) {
      var xm = (x06 + x12) / 2, ym = (y06 + y12) / 2;
      if (child = node[3]) quads.push(new quad_default(child, xm, ym, x12, y12));
      if (child = node[2]) quads.push(new quad_default(child, x06, ym, xm, y12));
      if (child = node[1]) quads.push(new quad_default(child, xm, y06, x12, ym));
      if (child = node[0]) quads.push(new quad_default(child, x06, y06, xm, ym));
    }
  }
  return this;
}

// node_modules/d3-quadtree/src/visitAfter.js
function visitAfter_default(callback) {
  var quads = [], next = [], q;
  if (this._root) quads.push(new quad_default(this._root, this._x0, this._y0, this._x1, this._y1));
  while (q = quads.pop()) {
    var node = q.node;
    if (node.length) {
      var child, x06 = q.x0, y06 = q.y0, x12 = q.x1, y12 = q.y1, xm = (x06 + x12) / 2, ym = (y06 + y12) / 2;
      if (child = node[0]) quads.push(new quad_default(child, x06, y06, xm, ym));
      if (child = node[1]) quads.push(new quad_default(child, xm, y06, x12, ym));
      if (child = node[2]) quads.push(new quad_default(child, x06, ym, xm, y12));
      if (child = node[3]) quads.push(new quad_default(child, xm, ym, x12, y12));
    }
    next.push(q);
  }
  while (q = next.pop()) {
    callback(q.node, q.x0, q.y0, q.x1, q.y1);
  }
  return this;
}

// node_modules/d3-quadtree/src/x.js
function defaultX2(d) {
  return d[0];
}
function x_default(_) {
  return arguments.length ? (this._x = _, this) : this._x;
}

// node_modules/d3-quadtree/src/y.js
function defaultY2(d) {
  return d[1];
}
function y_default(_) {
  return arguments.length ? (this._y = _, this) : this._y;
}

// node_modules/d3-quadtree/src/quadtree.js
function quadtree(nodes, x3, y3) {
  var tree2 = new Quadtree(x3 == null ? defaultX2 : x3, y3 == null ? defaultY2 : y3, NaN, NaN, NaN, NaN);
  return nodes == null ? tree2 : tree2.addAll(nodes);
}
function Quadtree(x3, y3, x06, y06, x12, y12) {
  this._x = x3;
  this._y = y3;
  this._x0 = x06;
  this._y0 = y06;
  this._x1 = x12;
  this._y1 = y12;
  this._root = void 0;
}
function leaf_copy(leaf) {
  var copy3 = { data: leaf.data }, next = copy3;
  while (leaf = leaf.next) next = next.next = { data: leaf.data };
  return copy3;
}
var treeProto = quadtree.prototype = Quadtree.prototype;
treeProto.copy = function() {
  var copy3 = new Quadtree(this._x, this._y, this._x0, this._y0, this._x1, this._y1), node = this._root, nodes, child;
  if (!node) return copy3;
  if (!node.length) return copy3._root = leaf_copy(node), copy3;
  nodes = [{ source: node, target: copy3._root = new Array(4) }];
  while (node = nodes.pop()) {
    for (var i = 0; i < 4; ++i) {
      if (child = node.source[i]) {
        if (child.length) nodes.push({ source: child, target: node.target[i] = new Array(4) });
        else node.target[i] = leaf_copy(child);
      }
    }
  }
  return copy3;
};
treeProto.add = add_default;
treeProto.addAll = addAll;
treeProto.cover = cover_default;
treeProto.data = data_default2;
treeProto.extent = extent_default;
treeProto.find = find_default;
treeProto.remove = remove_default3;
treeProto.removeAll = removeAll;
treeProto.root = root_default;
treeProto.size = size_default2;
treeProto.visit = visit_default;
treeProto.visitAfter = visitAfter_default;
treeProto.x = x_default;
treeProto.y = y_default;

// node_modules/d3-force/src/simulation.js
var initialAngle = Math.PI * (3 - Math.sqrt(5));

// node_modules/d3-format/src/formatDecimal.js
function formatDecimal_default(x3) {
  return Math.abs(x3 = Math.round(x3)) >= 1e21 ? x3.toLocaleString("en").replace(/,/g, "") : x3.toString(10);
}
function formatDecimalParts(x3, p) {
  if (!isFinite(x3) || x3 === 0) return null;
  var i = (x3 = p ? x3.toExponential(p - 1) : x3.toExponential()).indexOf("e"), coefficient = x3.slice(0, i);
  return [
    coefficient.length > 1 ? coefficient[0] + coefficient.slice(2) : coefficient,
    +x3.slice(i + 1)
  ];
}

// node_modules/d3-format/src/exponent.js
function exponent_default(x3) {
  return x3 = formatDecimalParts(Math.abs(x3)), x3 ? x3[1] : NaN;
}

// node_modules/d3-format/src/formatGroup.js
function formatGroup_default(grouping, thousands) {
  return function(value, width) {
    var i = value.length, t = [], j = 0, g = grouping[0], length3 = 0;
    while (i > 0 && g > 0) {
      if (length3 + g + 1 > width) g = Math.max(1, width - length3);
      t.push(value.substring(i -= g, i + g));
      if ((length3 += g + 1) > width) break;
      g = grouping[j = (j + 1) % grouping.length];
    }
    return t.reverse().join(thousands);
  };
}

// node_modules/d3-format/src/formatNumerals.js
function formatNumerals_default(numerals) {
  return function(value) {
    return value.replace(/[0-9]/g, function(i) {
      return numerals[+i];
    });
  };
}

// node_modules/d3-format/src/formatSpecifier.js
var re = /^(?:(.)?([<>=^]))?([+\-( ])?([$#])?(0)?(\d+)?(,)?(\.\d+)?(~)?([a-z%])?$/i;
function formatSpecifier(specifier) {
  if (!(match = re.exec(specifier))) throw new Error("invalid format: " + specifier);
  var match;
  return new FormatSpecifier({
    fill: match[1],
    align: match[2],
    sign: match[3],
    symbol: match[4],
    zero: match[5],
    width: match[6],
    comma: match[7],
    precision: match[8] && match[8].slice(1),
    trim: match[9],
    type: match[10]
  });
}
formatSpecifier.prototype = FormatSpecifier.prototype;
function FormatSpecifier(specifier) {
  this.fill = specifier.fill === void 0 ? " " : specifier.fill + "";
  this.align = specifier.align === void 0 ? ">" : specifier.align + "";
  this.sign = specifier.sign === void 0 ? "-" : specifier.sign + "";
  this.symbol = specifier.symbol === void 0 ? "" : specifier.symbol + "";
  this.zero = !!specifier.zero;
  this.width = specifier.width === void 0 ? void 0 : +specifier.width;
  this.comma = !!specifier.comma;
  this.precision = specifier.precision === void 0 ? void 0 : +specifier.precision;
  this.trim = !!specifier.trim;
  this.type = specifier.type === void 0 ? "" : specifier.type + "";
}
FormatSpecifier.prototype.toString = function() {
  return this.fill + this.align + this.sign + this.symbol + (this.zero ? "0" : "") + (this.width === void 0 ? "" : Math.max(1, this.width | 0)) + (this.comma ? "," : "") + (this.precision === void 0 ? "" : "." + Math.max(0, this.precision | 0)) + (this.trim ? "~" : "") + this.type;
};

// node_modules/d3-format/src/formatTrim.js
function formatTrim_default(s2) {
  out: for (var n = s2.length, i = 1, i0 = -1, i1; i < n; ++i) {
    switch (s2[i]) {
      case ".":
        i0 = i1 = i;
        break;
      case "0":
        if (i0 === 0) i0 = i;
        i1 = i;
        break;
      default:
        if (!+s2[i]) break out;
        if (i0 > 0) i0 = 0;
        break;
    }
  }
  return i0 > 0 ? s2.slice(0, i0) + s2.slice(i1 + 1) : s2;
}

// node_modules/d3-format/src/formatPrefixAuto.js
var prefixExponent;
function formatPrefixAuto_default(x3, p) {
  var d = formatDecimalParts(x3, p);
  if (!d) return prefixExponent = void 0, x3.toPrecision(p);
  var coefficient = d[0], exponent2 = d[1], i = exponent2 - (prefixExponent = Math.max(-8, Math.min(8, Math.floor(exponent2 / 3))) * 3) + 1, n = coefficient.length;
  return i === n ? coefficient : i > n ? coefficient + new Array(i - n + 1).join("0") : i > 0 ? coefficient.slice(0, i) + "." + coefficient.slice(i) : "0." + new Array(1 - i).join("0") + formatDecimalParts(x3, Math.max(0, p + i - 1))[0];
}

// node_modules/d3-format/src/formatRounded.js
function formatRounded_default(x3, p) {
  var d = formatDecimalParts(x3, p);
  if (!d) return x3 + "";
  var coefficient = d[0], exponent2 = d[1];
  return exponent2 < 0 ? "0." + new Array(-exponent2).join("0") + coefficient : coefficient.length > exponent2 + 1 ? coefficient.slice(0, exponent2 + 1) + "." + coefficient.slice(exponent2 + 1) : coefficient + new Array(exponent2 - coefficient.length + 2).join("0");
}

// node_modules/d3-format/src/formatTypes.js
var formatTypes_default = {
  "%": (x3, p) => (x3 * 100).toFixed(p),
  "b": (x3) => Math.round(x3).toString(2),
  "c": (x3) => x3 + "",
  "d": formatDecimal_default,
  "e": (x3, p) => x3.toExponential(p),
  "f": (x3, p) => x3.toFixed(p),
  "g": (x3, p) => x3.toPrecision(p),
  "o": (x3) => Math.round(x3).toString(8),
  "p": (x3, p) => formatRounded_default(x3 * 100, p),
  "r": formatRounded_default,
  "s": formatPrefixAuto_default,
  "X": (x3) => Math.round(x3).toString(16).toUpperCase(),
  "x": (x3) => Math.round(x3).toString(16)
};

// node_modules/d3-format/src/identity.js
function identity_default2(x3) {
  return x3;
}

// node_modules/d3-format/src/locale.js
var map3 = Array.prototype.map;
var prefixes = ["y", "z", "a", "f", "p", "n", "µ", "m", "", "k", "M", "G", "T", "P", "E", "Z", "Y"];
function locale_default(locale3) {
  var group3 = locale3.grouping === void 0 || locale3.thousands === void 0 ? identity_default2 : formatGroup_default(map3.call(locale3.grouping, Number), locale3.thousands + ""), currencyPrefix = locale3.currency === void 0 ? "" : locale3.currency[0] + "", currencySuffix = locale3.currency === void 0 ? "" : locale3.currency[1] + "", decimal = locale3.decimal === void 0 ? "." : locale3.decimal + "", numerals = locale3.numerals === void 0 ? identity_default2 : formatNumerals_default(map3.call(locale3.numerals, String)), percent = locale3.percent === void 0 ? "%" : locale3.percent + "", minus = locale3.minus === void 0 ? "−" : locale3.minus + "", nan = locale3.nan === void 0 ? "NaN" : locale3.nan + "";
  function newFormat(specifier, options) {
    specifier = formatSpecifier(specifier);
    var fill = specifier.fill, align = specifier.align, sign3 = specifier.sign, symbol2 = specifier.symbol, zero3 = specifier.zero, width = specifier.width, comma = specifier.comma, precision = specifier.precision, trim = specifier.trim, type2 = specifier.type;
    if (type2 === "n") comma = true, type2 = "g";
    else if (!formatTypes_default[type2]) precision === void 0 && (precision = 12), trim = true, type2 = "g";
    if (zero3 || fill === "0" && align === "=") zero3 = true, fill = "0", align = "=";
    var prefix = (options && options.prefix !== void 0 ? options.prefix : "") + (symbol2 === "$" ? currencyPrefix : symbol2 === "#" && /[boxX]/.test(type2) ? "0" + type2.toLowerCase() : ""), suffix = (symbol2 === "$" ? currencySuffix : /[%p]/.test(type2) ? percent : "") + (options && options.suffix !== void 0 ? options.suffix : "");
    var formatType = formatTypes_default[type2], maybeSuffix = /[defgprs%]/.test(type2);
    precision = precision === void 0 ? 6 : /[gprs]/.test(type2) ? Math.max(1, Math.min(21, precision)) : Math.max(0, Math.min(20, precision));
    function format3(value) {
      var valuePrefix = prefix, valueSuffix = suffix, i, n, c4;
      if (type2 === "c") {
        valueSuffix = formatType(value) + valueSuffix;
        value = "";
      } else {
        value = +value;
        var valueNegative = value < 0 || 1 / value < 0;
        value = isNaN(value) ? nan : formatType(Math.abs(value), precision);
        if (trim) value = formatTrim_default(value);
        if (valueNegative && +value === 0 && sign3 !== "+") valueNegative = false;
        valuePrefix = (valueNegative ? sign3 === "(" ? sign3 : minus : sign3 === "-" || sign3 === "(" ? "" : sign3) + valuePrefix;
        valueSuffix = (type2 === "s" && !isNaN(value) && prefixExponent !== void 0 ? prefixes[8 + prefixExponent / 3] : "") + valueSuffix + (valueNegative && sign3 === "(" ? ")" : "");
        if (maybeSuffix) {
          i = -1, n = value.length;
          while (++i < n) {
            if (c4 = value.charCodeAt(i), 48 > c4 || c4 > 57) {
              valueSuffix = (c4 === 46 ? decimal + value.slice(i + 1) : value.slice(i)) + valueSuffix;
              value = value.slice(0, i);
              break;
            }
          }
        }
      }
      if (comma && !zero3) value = group3(value, Infinity);
      var length3 = valuePrefix.length + value.length + valueSuffix.length, padding = length3 < width ? new Array(width - length3 + 1).join(fill) : "";
      if (comma && zero3) value = group3(padding + value, padding.length ? width - valueSuffix.length : Infinity), padding = "";
      switch (align) {
        case "<":
          value = valuePrefix + value + valueSuffix + padding;
          break;
        case "=":
          value = valuePrefix + padding + value + valueSuffix;
          break;
        case "^":
          value = padding.slice(0, length3 = padding.length >> 1) + valuePrefix + value + valueSuffix + padding.slice(length3);
          break;
        default:
          value = padding + valuePrefix + value + valueSuffix;
          break;
      }
      return numerals(value);
    }
    format3.toString = function() {
      return specifier + "";
    };
    return format3;
  }
  function formatPrefix2(specifier, value) {
    var e = Math.max(-8, Math.min(8, Math.floor(exponent_default(value) / 3))) * 3, k2 = Math.pow(10, -e), f = newFormat((specifier = formatSpecifier(specifier), specifier.type = "f", specifier), { suffix: prefixes[8 + e / 3] });
    return function(value2) {
      return f(k2 * value2);
    };
  }
  return {
    format: newFormat,
    formatPrefix: formatPrefix2
  };
}

// node_modules/d3-format/src/defaultLocale.js
var locale;
var format;
var formatPrefix;
defaultLocale({
  thousands: ",",
  grouping: [3],
  currency: ["$", ""]
});
function defaultLocale(definition) {
  locale = locale_default(definition);
  format = locale.format;
  formatPrefix = locale.formatPrefix;
  return locale;
}

// node_modules/d3-format/src/precisionFixed.js
function precisionFixed_default(step) {
  return Math.max(0, -exponent_default(Math.abs(step)));
}

// node_modules/d3-format/src/precisionPrefix.js
function precisionPrefix_default(step, value) {
  return Math.max(0, Math.max(-8, Math.min(8, Math.floor(exponent_default(value) / 3))) * 3 - exponent_default(Math.abs(step)));
}

// node_modules/d3-format/src/precisionRound.js
function precisionRound_default(step, max5) {
  step = Math.abs(step), max5 = Math.abs(max5) - step;
  return Math.max(0, exponent_default(max5) - exponent_default(step)) + 1;
}

// node_modules/d3-geo/src/math.js
var epsilon7 = 1e-6;
var epsilon22 = 1e-12;
var pi4 = Math.PI;
var halfPi3 = pi4 / 2;
var quarterPi = pi4 / 4;
var tau5 = pi4 * 2;
var degrees3 = 180 / pi4;
var radians2 = pi4 / 180;
var abs3 = Math.abs;
var atan = Math.atan;
var atan2 = Math.atan2;
var cos2 = Math.cos;
var ceil = Math.ceil;
var exp = Math.exp;
var hypot = Math.hypot;
var log = Math.log;
var pow2 = Math.pow;
var sin2 = Math.sin;
var sign = Math.sign || function(x3) {
  return x3 > 0 ? 1 : x3 < 0 ? -1 : 0;
};
var sqrt = Math.sqrt;
var tan = Math.tan;
function acos(x3) {
  return x3 > 1 ? 0 : x3 < -1 ? pi4 : Math.acos(x3);
}
function asin(x3) {
  return x3 > 1 ? halfPi3 : x3 < -1 ? -halfPi3 : Math.asin(x3);
}

// node_modules/d3-geo/src/noop.js
function noop2() {
}

// node_modules/d3-geo/src/stream.js
function streamGeometry(geometry, stream) {
  if (geometry && streamGeometryType.hasOwnProperty(geometry.type)) {
    streamGeometryType[geometry.type](geometry, stream);
  }
}
var streamObjectType = {
  Feature: function(object, stream) {
    streamGeometry(object.geometry, stream);
  },
  FeatureCollection: function(object, stream) {
    var features = object.features, i = -1, n = features.length;
    while (++i < n) streamGeometry(features[i].geometry, stream);
  }
};
var streamGeometryType = {
  Sphere: function(object, stream) {
    stream.sphere();
  },
  Point: function(object, stream) {
    object = object.coordinates;
    stream.point(object[0], object[1], object[2]);
  },
  MultiPoint: function(object, stream) {
    var coordinates = object.coordinates, i = -1, n = coordinates.length;
    while (++i < n) object = coordinates[i], stream.point(object[0], object[1], object[2]);
  },
  LineString: function(object, stream) {
    streamLine(object.coordinates, stream, 0);
  },
  MultiLineString: function(object, stream) {
    var coordinates = object.coordinates, i = -1, n = coordinates.length;
    while (++i < n) streamLine(coordinates[i], stream, 0);
  },
  Polygon: function(object, stream) {
    streamPolygon(object.coordinates, stream);
  },
  MultiPolygon: function(object, stream) {
    var coordinates = object.coordinates, i = -1, n = coordinates.length;
    while (++i < n) streamPolygon(coordinates[i], stream);
  },
  GeometryCollection: function(object, stream) {
    var geometries = object.geometries, i = -1, n = geometries.length;
    while (++i < n) streamGeometry(geometries[i], stream);
  }
};
function streamLine(coordinates, stream, closed) {
  var i = -1, n = coordinates.length - closed, coordinate;
  stream.lineStart();
  while (++i < n) coordinate = coordinates[i], stream.point(coordinate[0], coordinate[1], coordinate[2]);
  stream.lineEnd();
}
function streamPolygon(coordinates, stream) {
  var i = -1, n = coordinates.length;
  stream.polygonStart();
  while (++i < n) streamLine(coordinates[i], stream, 1);
  stream.polygonEnd();
}
function stream_default(object, stream) {
  if (object && streamObjectType.hasOwnProperty(object.type)) {
    streamObjectType[object.type](object, stream);
  } else {
    streamGeometry(object, stream);
  }
}

// node_modules/d3-geo/src/area.js
var areaRingSum = new Adder();
var areaSum = new Adder();

// node_modules/d3-geo/src/cartesian.js
function spherical(cartesian2) {
  return [atan2(cartesian2[1], cartesian2[0]), asin(cartesian2[2])];
}
function cartesian(spherical2) {
  var lambda = spherical2[0], phi2 = spherical2[1], cosPhi = cos2(phi2);
  return [cosPhi * cos2(lambda), cosPhi * sin2(lambda), sin2(phi2)];
}
function cartesianDot(a2, b) {
  return a2[0] * b[0] + a2[1] * b[1] + a2[2] * b[2];
}
function cartesianCross(a2, b) {
  return [a2[1] * b[2] - a2[2] * b[1], a2[2] * b[0] - a2[0] * b[2], a2[0] * b[1] - a2[1] * b[0]];
}
function cartesianAddInPlace(a2, b) {
  a2[0] += b[0], a2[1] += b[1], a2[2] += b[2];
}
function cartesianScale(vector2, k2) {
  return [vector2[0] * k2, vector2[1] * k2, vector2[2] * k2];
}
function cartesianNormalizeInPlace(d) {
  var l = sqrt(d[0] * d[0] + d[1] * d[1] + d[2] * d[2]);
  d[0] /= l, d[1] /= l, d[2] /= l;
}

// node_modules/d3-geo/src/centroid.js
var W0;
var W1;
var X0;
var Y0;
var Z0;
var X1;
var Y1;
var Z1;
var X2;
var Y2;
var Z2;
var lambda00;
var phi00;
var x0;
var y0;
var z0;
var centroidStream = {
  sphere: noop2,
  point: centroidPoint,
  lineStart: centroidLineStart,
  lineEnd: centroidLineEnd,
  polygonStart: function() {
    centroidStream.lineStart = centroidRingStart;
    centroidStream.lineEnd = centroidRingEnd;
  },
  polygonEnd: function() {
    centroidStream.lineStart = centroidLineStart;
    centroidStream.lineEnd = centroidLineEnd;
  }
};
function centroidPoint(lambda, phi2) {
  lambda *= radians2, phi2 *= radians2;
  var cosPhi = cos2(phi2);
  centroidPointCartesian(cosPhi * cos2(lambda), cosPhi * sin2(lambda), sin2(phi2));
}
function centroidPointCartesian(x3, y3, z) {
  ++W0;
  X0 += (x3 - X0) / W0;
  Y0 += (y3 - Y0) / W0;
  Z0 += (z - Z0) / W0;
}
function centroidLineStart() {
  centroidStream.point = centroidLinePointFirst;
}
function centroidLinePointFirst(lambda, phi2) {
  lambda *= radians2, phi2 *= radians2;
  var cosPhi = cos2(phi2);
  x0 = cosPhi * cos2(lambda);
  y0 = cosPhi * sin2(lambda);
  z0 = sin2(phi2);
  centroidStream.point = centroidLinePoint;
  centroidPointCartesian(x0, y0, z0);
}
function centroidLinePoint(lambda, phi2) {
  lambda *= radians2, phi2 *= radians2;
  var cosPhi = cos2(phi2), x3 = cosPhi * cos2(lambda), y3 = cosPhi * sin2(lambda), z = sin2(phi2), w = atan2(sqrt((w = y0 * z - z0 * y3) * w + (w = z0 * x3 - x0 * z) * w + (w = x0 * y3 - y0 * x3) * w), x0 * x3 + y0 * y3 + z0 * z);
  W1 += w;
  X1 += w * (x0 + (x0 = x3));
  Y1 += w * (y0 + (y0 = y3));
  Z1 += w * (z0 + (z0 = z));
  centroidPointCartesian(x0, y0, z0);
}
function centroidLineEnd() {
  centroidStream.point = centroidPoint;
}
function centroidRingStart() {
  centroidStream.point = centroidRingPointFirst;
}
function centroidRingEnd() {
  centroidRingPoint(lambda00, phi00);
  centroidStream.point = centroidPoint;
}
function centroidRingPointFirst(lambda, phi2) {
  lambda00 = lambda, phi00 = phi2;
  lambda *= radians2, phi2 *= radians2;
  centroidStream.point = centroidRingPoint;
  var cosPhi = cos2(phi2);
  x0 = cosPhi * cos2(lambda);
  y0 = cosPhi * sin2(lambda);
  z0 = sin2(phi2);
  centroidPointCartesian(x0, y0, z0);
}
function centroidRingPoint(lambda, phi2) {
  lambda *= radians2, phi2 *= radians2;
  var cosPhi = cos2(phi2), x3 = cosPhi * cos2(lambda), y3 = cosPhi * sin2(lambda), z = sin2(phi2), cx = y0 * z - z0 * y3, cy = z0 * x3 - x0 * z, cz = x0 * y3 - y0 * x3, m = hypot(cx, cy, cz), w = asin(m), v2 = m && -w / m;
  X2.add(v2 * cx);
  Y2.add(v2 * cy);
  Z2.add(v2 * cz);
  W1 += w;
  X1 += w * (x0 + (x0 = x3));
  Y1 += w * (y0 + (y0 = y3));
  Z1 += w * (z0 + (z0 = z));
  centroidPointCartesian(x0, y0, z0);
}
function centroid_default(object) {
  W0 = W1 = X0 = Y0 = Z0 = X1 = Y1 = Z1 = 0;
  X2 = new Adder();
  Y2 = new Adder();
  Z2 = new Adder();
  stream_default(object, centroidStream);
  var x3 = +X2, y3 = +Y2, z = +Z2, m = hypot(x3, y3, z);
  if (m < epsilon22) {
    x3 = X1, y3 = Y1, z = Z1;
    if (W1 < epsilon7) x3 = X0, y3 = Y0, z = Z0;
    m = hypot(x3, y3, z);
    if (m < epsilon22) return [NaN, NaN];
  }
  return [atan2(y3, x3) * degrees3, asin(z / m) * degrees3];
}

// node_modules/d3-geo/src/compose.js
function compose_default(a2, b) {
  function compose(x3, y3) {
    return x3 = a2(x3, y3), b(x3[0], x3[1]);
  }
  if (a2.invert && b.invert) compose.invert = function(x3, y3) {
    return x3 = b.invert(x3, y3), x3 && a2.invert(x3[0], x3[1]);
  };
  return compose;
}

// node_modules/d3-geo/src/rotation.js
function rotationIdentity(lambda, phi2) {
  if (abs3(lambda) > pi4) lambda -= Math.round(lambda / tau5) * tau5;
  return [lambda, phi2];
}
rotationIdentity.invert = rotationIdentity;
function rotateRadians(deltaLambda, deltaPhi, deltaGamma) {
  return (deltaLambda %= tau5) ? deltaPhi || deltaGamma ? compose_default(rotationLambda(deltaLambda), rotationPhiGamma(deltaPhi, deltaGamma)) : rotationLambda(deltaLambda) : deltaPhi || deltaGamma ? rotationPhiGamma(deltaPhi, deltaGamma) : rotationIdentity;
}
function forwardRotationLambda(deltaLambda) {
  return function(lambda, phi2) {
    lambda += deltaLambda;
    if (abs3(lambda) > pi4) lambda -= Math.round(lambda / tau5) * tau5;
    return [lambda, phi2];
  };
}
function rotationLambda(deltaLambda) {
  var rotation = forwardRotationLambda(deltaLambda);
  rotation.invert = forwardRotationLambda(-deltaLambda);
  return rotation;
}
function rotationPhiGamma(deltaPhi, deltaGamma) {
  var cosDeltaPhi = cos2(deltaPhi), sinDeltaPhi = sin2(deltaPhi), cosDeltaGamma = cos2(deltaGamma), sinDeltaGamma = sin2(deltaGamma);
  function rotation(lambda, phi2) {
    var cosPhi = cos2(phi2), x3 = cos2(lambda) * cosPhi, y3 = sin2(lambda) * cosPhi, z = sin2(phi2), k2 = z * cosDeltaPhi + x3 * sinDeltaPhi;
    return [
      atan2(y3 * cosDeltaGamma - k2 * sinDeltaGamma, x3 * cosDeltaPhi - z * sinDeltaPhi),
      asin(k2 * cosDeltaGamma + y3 * sinDeltaGamma)
    ];
  }
  rotation.invert = function(lambda, phi2) {
    var cosPhi = cos2(phi2), x3 = cos2(lambda) * cosPhi, y3 = sin2(lambda) * cosPhi, z = sin2(phi2), k2 = z * cosDeltaGamma - y3 * sinDeltaGamma;
    return [
      atan2(y3 * cosDeltaGamma + z * sinDeltaGamma, x3 * cosDeltaPhi + k2 * sinDeltaPhi),
      asin(k2 * cosDeltaPhi - x3 * sinDeltaPhi)
    ];
  };
  return rotation;
}
function rotation_default(rotate) {
  rotate = rotateRadians(rotate[0] * radians2, rotate[1] * radians2, rotate.length > 2 ? rotate[2] * radians2 : 0);
  function forward(coordinates) {
    coordinates = rotate(coordinates[0] * radians2, coordinates[1] * radians2);
    return coordinates[0] *= degrees3, coordinates[1] *= degrees3, coordinates;
  }
  forward.invert = function(coordinates) {
    coordinates = rotate.invert(coordinates[0] * radians2, coordinates[1] * radians2);
    return coordinates[0] *= degrees3, coordinates[1] *= degrees3, coordinates;
  };
  return forward;
}

// node_modules/d3-geo/src/circle.js
function circleStream(stream, radius2, delta, direction, t03, t13) {
  if (!delta) return;
  var cosRadius = cos2(radius2), sinRadius = sin2(radius2), step = direction * delta;
  if (t03 == null) {
    t03 = radius2 + direction * tau5;
    t13 = radius2 - step / 2;
  } else {
    t03 = circleRadius(cosRadius, t03);
    t13 = circleRadius(cosRadius, t13);
    if (direction > 0 ? t03 < t13 : t03 > t13) t03 += direction * tau5;
  }
  for (var point6, t = t03; direction > 0 ? t > t13 : t < t13; t -= step) {
    point6 = spherical([cosRadius, -sinRadius * cos2(t), -sinRadius * sin2(t)]);
    stream.point(point6[0], point6[1]);
  }
}
function circleRadius(cosRadius, point6) {
  point6 = cartesian(point6), point6[0] -= cosRadius;
  cartesianNormalizeInPlace(point6);
  var radius2 = acos(-point6[1]);
  return ((-point6[2] < 0 ? -radius2 : radius2) + tau5 - epsilon7) % tau5;
}

// node_modules/d3-geo/src/clip/buffer.js
function buffer_default2() {
  var lines = [], line2;
  return {
    point: function(x3, y3, m) {
      line2.push([x3, y3, m]);
    },
    lineStart: function() {
      lines.push(line2 = []);
    },
    lineEnd: noop2,
    rejoin: function() {
      if (lines.length > 1) lines.push(lines.pop().concat(lines.shift()));
    },
    result: function() {
      var result = lines;
      lines = [];
      line2 = null;
      return result;
    }
  };
}

// node_modules/d3-geo/src/pointEqual.js
function pointEqual_default(a2, b) {
  return abs3(a2[0] - b[0]) < epsilon7 && abs3(a2[1] - b[1]) < epsilon7;
}

// node_modules/d3-geo/src/clip/rejoin.js
function Intersection(point6, points, other, entry) {
  this.x = point6;
  this.z = points;
  this.o = other;
  this.e = entry;
  this.v = false;
  this.n = this.p = null;
}
function rejoin_default(segments, compareIntersection2, startInside, interpolate, stream) {
  var subject = [], clip = [], i, n;
  segments.forEach(function(segment) {
    if ((n2 = segment.length - 1) <= 0) return;
    var n2, p0 = segment[0], p1 = segment[n2], x3;
    if (pointEqual_default(p0, p1)) {
      if (!p0[2] && !p1[2]) {
        stream.lineStart();
        for (i = 0; i < n2; ++i) stream.point((p0 = segment[i])[0], p0[1]);
        stream.lineEnd();
        return;
      }
      p1[0] += 2 * epsilon7;
    }
    subject.push(x3 = new Intersection(p0, segment, null, true));
    clip.push(x3.o = new Intersection(p0, null, x3, false));
    subject.push(x3 = new Intersection(p1, segment, null, false));
    clip.push(x3.o = new Intersection(p1, null, x3, true));
  });
  if (!subject.length) return;
  clip.sort(compareIntersection2);
  link(subject);
  link(clip);
  for (i = 0, n = clip.length; i < n; ++i) {
    clip[i].e = startInside = !startInside;
  }
  var start2 = subject[0], points, point6;
  while (1) {
    var current = start2, isSubject = true;
    while (current.v) if ((current = current.n) === start2) return;
    points = current.z;
    stream.lineStart();
    do {
      current.v = current.o.v = true;
      if (current.e) {
        if (isSubject) {
          for (i = 0, n = points.length; i < n; ++i) stream.point((point6 = points[i])[0], point6[1]);
        } else {
          interpolate(current.x, current.n.x, 1, stream);
        }
        current = current.n;
      } else {
        if (isSubject) {
          points = current.p.z;
          for (i = points.length - 1; i >= 0; --i) stream.point((point6 = points[i])[0], point6[1]);
        } else {
          interpolate(current.x, current.p.x, -1, stream);
        }
        current = current.p;
      }
      current = current.o;
      points = current.z;
      isSubject = !isSubject;
    } while (!current.v);
    stream.lineEnd();
  }
}
function link(array4) {
  if (!(n = array4.length)) return;
  var n, i = 0, a2 = array4[0], b;
  while (++i < n) {
    a2.n = b = array4[i];
    b.p = a2;
    a2 = b;
  }
  a2.n = b = array4[0];
  b.p = a2;
}

// node_modules/d3-geo/src/polygonContains.js
function longitude(point6) {
  return abs3(point6[0]) <= pi4 ? point6[0] : sign(point6[0]) * ((abs3(point6[0]) + pi4) % tau5 - pi4);
}
function polygonContains_default(polygon, point6) {
  var lambda = longitude(point6), phi2 = point6[1], sinPhi = sin2(phi2), normal = [sin2(lambda), -cos2(lambda), 0], angle = 0, winding = 0;
  var sum4 = new Adder();
  if (sinPhi === 1) phi2 = halfPi3 + epsilon7;
  else if (sinPhi === -1) phi2 = -halfPi3 - epsilon7;
  for (var i = 0, n = polygon.length; i < n; ++i) {
    if (!(m = (ring = polygon[i]).length)) continue;
    var ring, m, point0 = ring[m - 1], lambda0 = longitude(point0), phi0 = point0[1] / 2 + quarterPi, sinPhi0 = sin2(phi0), cosPhi0 = cos2(phi0);
    for (var j = 0; j < m; ++j, lambda0 = lambda1, sinPhi0 = sinPhi1, cosPhi0 = cosPhi1, point0 = point1) {
      var point1 = ring[j], lambda1 = longitude(point1), phi1 = point1[1] / 2 + quarterPi, sinPhi1 = sin2(phi1), cosPhi1 = cos2(phi1), delta = lambda1 - lambda0, sign3 = delta >= 0 ? 1 : -1, absDelta = sign3 * delta, antimeridian = absDelta > pi4, k2 = sinPhi0 * sinPhi1;
      sum4.add(atan2(k2 * sign3 * sin2(absDelta), cosPhi0 * cosPhi1 + k2 * cos2(absDelta)));
      angle += antimeridian ? delta + sign3 * tau5 : delta;
      if (antimeridian ^ lambda0 >= lambda ^ lambda1 >= lambda) {
        var arc = cartesianCross(cartesian(point0), cartesian(point1));
        cartesianNormalizeInPlace(arc);
        var intersection2 = cartesianCross(normal, arc);
        cartesianNormalizeInPlace(intersection2);
        var phiArc = (antimeridian ^ delta >= 0 ? -1 : 1) * asin(intersection2[2]);
        if (phi2 > phiArc || phi2 === phiArc && (arc[0] || arc[1])) {
          winding += antimeridian ^ delta >= 0 ? 1 : -1;
        }
      }
    }
  }
  return (angle < -epsilon7 || angle < epsilon7 && sum4 < -epsilon22) ^ winding & 1;
}

// node_modules/d3-geo/src/clip/index.js
function clip_default(pointVisible, clipLine, interpolate, start2) {
  return function(sink) {
    var line2 = clipLine(sink), ringBuffer = buffer_default2(), ringSink = clipLine(ringBuffer), polygonStarted = false, polygon, segments, ring;
    var clip = {
      point: point6,
      lineStart,
      lineEnd,
      polygonStart: function() {
        clip.point = pointRing;
        clip.lineStart = ringStart;
        clip.lineEnd = ringEnd;
        segments = [];
        polygon = [];
      },
      polygonEnd: function() {
        clip.point = point6;
        clip.lineStart = lineStart;
        clip.lineEnd = lineEnd;
        segments = merge(segments);
        var startInside = polygonContains_default(polygon, start2);
        if (segments.length) {
          if (!polygonStarted) sink.polygonStart(), polygonStarted = true;
          rejoin_default(segments, compareIntersection, startInside, interpolate, sink);
        } else if (startInside) {
          if (!polygonStarted) sink.polygonStart(), polygonStarted = true;
          sink.lineStart();
          interpolate(null, null, 1, sink);
          sink.lineEnd();
        }
        if (polygonStarted) sink.polygonEnd(), polygonStarted = false;
        segments = polygon = null;
      },
      sphere: function() {
        sink.polygonStart();
        sink.lineStart();
        interpolate(null, null, 1, sink);
        sink.lineEnd();
        sink.polygonEnd();
      }
    };
    function point6(lambda, phi2) {
      if (pointVisible(lambda, phi2)) sink.point(lambda, phi2);
    }
    function pointLine(lambda, phi2) {
      line2.point(lambda, phi2);
    }
    function lineStart() {
      clip.point = pointLine;
      line2.lineStart();
    }
    function lineEnd() {
      clip.point = point6;
      line2.lineEnd();
    }
    function pointRing(lambda, phi2) {
      ring.push([lambda, phi2]);
      ringSink.point(lambda, phi2);
    }
    function ringStart() {
      ringSink.lineStart();
      ring = [];
    }
    function ringEnd() {
      pointRing(ring[0][0], ring[0][1]);
      ringSink.lineEnd();
      var clean = ringSink.clean(), ringSegments = ringBuffer.result(), i, n = ringSegments.length, m, segment, point7;
      ring.pop();
      polygon.push(ring);
      ring = null;
      if (!n) return;
      if (clean & 1) {
        segment = ringSegments[0];
        if ((m = segment.length - 1) > 0) {
          if (!polygonStarted) sink.polygonStart(), polygonStarted = true;
          sink.lineStart();
          for (i = 0; i < m; ++i) sink.point((point7 = segment[i])[0], point7[1]);
          sink.lineEnd();
        }
        return;
      }
      if (n > 1 && clean & 2) ringSegments.push(ringSegments.pop().concat(ringSegments.shift()));
      segments.push(ringSegments.filter(validSegment));
    }
    return clip;
  };
}
function validSegment(segment) {
  return segment.length > 1;
}
function compareIntersection(a2, b) {
  return ((a2 = a2.x)[0] < 0 ? a2[1] - halfPi3 - epsilon7 : halfPi3 - a2[1]) - ((b = b.x)[0] < 0 ? b[1] - halfPi3 - epsilon7 : halfPi3 - b[1]);
}

// node_modules/d3-geo/src/clip/antimeridian.js
var antimeridian_default = clip_default(
  function() {
    return true;
  },
  clipAntimeridianLine,
  clipAntimeridianInterpolate,
  [-pi4, -halfPi3]
);
function clipAntimeridianLine(stream) {
  var lambda0 = NaN, phi0 = NaN, sign0 = NaN, clean;
  return {
    lineStart: function() {
      stream.lineStart();
      clean = 1;
    },
    point: function(lambda1, phi1) {
      var sign1 = lambda1 > 0 ? pi4 : -pi4, delta = abs3(lambda1 - lambda0);
      if (abs3(delta - pi4) < epsilon7) {
        stream.point(lambda0, phi0 = (phi0 + phi1) / 2 > 0 ? halfPi3 : -halfPi3);
        stream.point(sign0, phi0);
        stream.lineEnd();
        stream.lineStart();
        stream.point(sign1, phi0);
        stream.point(lambda1, phi0);
        clean = 0;
      } else if (sign0 !== sign1 && delta >= pi4) {
        if (abs3(lambda0 - sign0) < epsilon7) lambda0 -= sign0 * epsilon7;
        if (abs3(lambda1 - sign1) < epsilon7) lambda1 -= sign1 * epsilon7;
        phi0 = clipAntimeridianIntersect(lambda0, phi0, lambda1, phi1);
        stream.point(sign0, phi0);
        stream.lineEnd();
        stream.lineStart();
        stream.point(sign1, phi0);
        clean = 0;
      }
      stream.point(lambda0 = lambda1, phi0 = phi1);
      sign0 = sign1;
    },
    lineEnd: function() {
      stream.lineEnd();
      lambda0 = phi0 = NaN;
    },
    clean: function() {
      return 2 - clean;
    }
  };
}
function clipAntimeridianIntersect(lambda0, phi0, lambda1, phi1) {
  var cosPhi0, cosPhi1, sinLambda0Lambda1 = sin2(lambda0 - lambda1);
  return abs3(sinLambda0Lambda1) > epsilon7 ? atan((sin2(phi0) * (cosPhi1 = cos2(phi1)) * sin2(lambda1) - sin2(phi1) * (cosPhi0 = cos2(phi0)) * sin2(lambda0)) / (cosPhi0 * cosPhi1 * sinLambda0Lambda1)) : (phi0 + phi1) / 2;
}
function clipAntimeridianInterpolate(from, to, direction, stream) {
  var phi2;
  if (from == null) {
    phi2 = direction * halfPi3;
    stream.point(-pi4, phi2);
    stream.point(0, phi2);
    stream.point(pi4, phi2);
    stream.point(pi4, 0);
    stream.point(pi4, -phi2);
    stream.point(0, -phi2);
    stream.point(-pi4, -phi2);
    stream.point(-pi4, 0);
    stream.point(-pi4, phi2);
  } else if (abs3(from[0] - to[0]) > epsilon7) {
    var lambda = from[0] < to[0] ? pi4 : -pi4;
    phi2 = direction * lambda / 2;
    stream.point(-lambda, phi2);
    stream.point(0, phi2);
    stream.point(lambda, phi2);
  } else {
    stream.point(to[0], to[1]);
  }
}

// node_modules/d3-geo/src/clip/circle.js
function circle_default(radius2) {
  var cr = cos2(radius2), delta = 2 * radians2, smallRadius = cr > 0, notHemisphere = abs3(cr) > epsilon7;
  function interpolate(from, to, direction, stream) {
    circleStream(stream, radius2, delta, direction, from, to);
  }
  function visible(lambda, phi2) {
    return cos2(lambda) * cos2(phi2) > cr;
  }
  function clipLine(stream) {
    var point0, c0, v0, v00, clean;
    return {
      lineStart: function() {
        v00 = v0 = false;
        clean = 1;
      },
      point: function(lambda, phi2) {
        var point1 = [lambda, phi2], point22, v2 = visible(lambda, phi2), c4 = smallRadius ? v2 ? 0 : code(lambda, phi2) : v2 ? code(lambda + (lambda < 0 ? pi4 : -pi4), phi2) : 0;
        if (!point0 && (v00 = v0 = v2)) stream.lineStart();
        if (v2 !== v0) {
          point22 = intersect(point0, point1);
          if (!point22 || pointEqual_default(point0, point22) || pointEqual_default(point1, point22))
            point1[2] = 1;
        }
        if (v2 !== v0) {
          clean = 0;
          if (v2) {
            stream.lineStart();
            point22 = intersect(point1, point0);
            stream.point(point22[0], point22[1]);
          } else {
            point22 = intersect(point0, point1);
            stream.point(point22[0], point22[1], 2);
            stream.lineEnd();
          }
          point0 = point22;
        } else if (notHemisphere && point0 && smallRadius ^ v2) {
          var t;
          if (!(c4 & c0) && (t = intersect(point1, point0, true))) {
            clean = 0;
            if (smallRadius) {
              stream.lineStart();
              stream.point(t[0][0], t[0][1]);
              stream.point(t[1][0], t[1][1]);
              stream.lineEnd();
            } else {
              stream.point(t[1][0], t[1][1]);
              stream.lineEnd();
              stream.lineStart();
              stream.point(t[0][0], t[0][1], 3);
            }
          }
        }
        if (v2 && (!point0 || !pointEqual_default(point0, point1))) {
          stream.point(point1[0], point1[1]);
        }
        point0 = point1, v0 = v2, c0 = c4;
      },
      lineEnd: function() {
        if (v0) stream.lineEnd();
        point0 = null;
      },
      // Rejoin first and last segments if there were intersections and the first
      // and last points were visible.
      clean: function() {
        return clean | (v00 && v0) << 1;
      }
    };
  }
  function intersect(a2, b, two) {
    var pa = cartesian(a2), pb = cartesian(b);
    var n1 = [1, 0, 0], n2 = cartesianCross(pa, pb), n2n2 = cartesianDot(n2, n2), n1n2 = n2[0], determinant = n2n2 - n1n2 * n1n2;
    if (!determinant) return !two && a2;
    var c1 = cr * n2n2 / determinant, c22 = -cr * n1n2 / determinant, n1xn2 = cartesianCross(n1, n2), A5 = cartesianScale(n1, c1), B3 = cartesianScale(n2, c22);
    cartesianAddInPlace(A5, B3);
    var u4 = n1xn2, w = cartesianDot(A5, u4), uu = cartesianDot(u4, u4), t22 = w * w - uu * (cartesianDot(A5, A5) - 1);
    if (t22 < 0) return;
    var t = sqrt(t22), q = cartesianScale(u4, (-w - t) / uu);
    cartesianAddInPlace(q, A5);
    q = spherical(q);
    if (!two) return q;
    var lambda0 = a2[0], lambda1 = b[0], phi0 = a2[1], phi1 = b[1], z;
    if (lambda1 < lambda0) z = lambda0, lambda0 = lambda1, lambda1 = z;
    var delta2 = lambda1 - lambda0, polar = abs3(delta2 - pi4) < epsilon7, meridian = polar || delta2 < epsilon7;
    if (!polar && phi1 < phi0) z = phi0, phi0 = phi1, phi1 = z;
    if (meridian ? polar ? phi0 + phi1 > 0 ^ q[1] < (abs3(q[0] - lambda0) < epsilon7 ? phi0 : phi1) : phi0 <= q[1] && q[1] <= phi1 : delta2 > pi4 ^ (lambda0 <= q[0] && q[0] <= lambda1)) {
      var q1 = cartesianScale(u4, (-w + t) / uu);
      cartesianAddInPlace(q1, A5);
      return [q, spherical(q1)];
    }
  }
  function code(lambda, phi2) {
    var r = smallRadius ? radius2 : pi4 - radius2, code2 = 0;
    if (lambda < -r) code2 |= 1;
    else if (lambda > r) code2 |= 2;
    if (phi2 < -r) code2 |= 4;
    else if (phi2 > r) code2 |= 8;
    return code2;
  }
  return clip_default(visible, clipLine, interpolate, smallRadius ? [0, -radius2] : [-pi4, radius2 - pi4]);
}

// node_modules/d3-geo/src/clip/line.js
function line_default(a2, b, x06, y06, x12, y12) {
  var ax = a2[0], ay = a2[1], bx = b[0], by = b[1], t03 = 0, t13 = 1, dx = bx - ax, dy = by - ay, r;
  r = x06 - ax;
  if (!dx && r > 0) return;
  r /= dx;
  if (dx < 0) {
    if (r < t03) return;
    if (r < t13) t13 = r;
  } else if (dx > 0) {
    if (r > t13) return;
    if (r > t03) t03 = r;
  }
  r = x12 - ax;
  if (!dx && r < 0) return;
  r /= dx;
  if (dx < 0) {
    if (r > t13) return;
    if (r > t03) t03 = r;
  } else if (dx > 0) {
    if (r < t03) return;
    if (r < t13) t13 = r;
  }
  r = y06 - ay;
  if (!dy && r > 0) return;
  r /= dy;
  if (dy < 0) {
    if (r < t03) return;
    if (r < t13) t13 = r;
  } else if (dy > 0) {
    if (r > t13) return;
    if (r > t03) t03 = r;
  }
  r = y12 - ay;
  if (!dy && r < 0) return;
  r /= dy;
  if (dy < 0) {
    if (r > t13) return;
    if (r > t03) t03 = r;
  } else if (dy > 0) {
    if (r < t03) return;
    if (r < t13) t13 = r;
  }
  if (t03 > 0) a2[0] = ax + t03 * dx, a2[1] = ay + t03 * dy;
  if (t13 < 1) b[0] = ax + t13 * dx, b[1] = ay + t13 * dy;
  return true;
}

// node_modules/d3-geo/src/clip/rectangle.js
var clipMax = 1e9;
var clipMin = -clipMax;
function clipRectangle(x06, y06, x12, y12) {
  function visible(x3, y3) {
    return x06 <= x3 && x3 <= x12 && y06 <= y3 && y3 <= y12;
  }
  function interpolate(from, to, direction, stream) {
    var a2 = 0, a1 = 0;
    if (from == null || (a2 = corner(from, direction)) !== (a1 = corner(to, direction)) || comparePoint(from, to) < 0 ^ direction > 0) {
      do
        stream.point(a2 === 0 || a2 === 3 ? x06 : x12, a2 > 1 ? y12 : y06);
      while ((a2 = (a2 + direction + 4) % 4) !== a1);
    } else {
      stream.point(to[0], to[1]);
    }
  }
  function corner(p, direction) {
    return abs3(p[0] - x06) < epsilon7 ? direction > 0 ? 0 : 3 : abs3(p[0] - x12) < epsilon7 ? direction > 0 ? 2 : 1 : abs3(p[1] - y06) < epsilon7 ? direction > 0 ? 1 : 0 : direction > 0 ? 3 : 2;
  }
  function compareIntersection2(a2, b) {
    return comparePoint(a2.x, b.x);
  }
  function comparePoint(a2, b) {
    var ca3 = corner(a2, 1), cb = corner(b, 1);
    return ca3 !== cb ? ca3 - cb : ca3 === 0 ? b[1] - a2[1] : ca3 === 1 ? a2[0] - b[0] : ca3 === 2 ? a2[1] - b[1] : b[0] - a2[0];
  }
  return function(stream) {
    var activeStream = stream, bufferStream = buffer_default2(), segments, polygon, ring, x__, y__, v__, x_, y_, v_, first2, clean;
    var clipStream = {
      point: point6,
      lineStart,
      lineEnd,
      polygonStart,
      polygonEnd
    };
    function point6(x3, y3) {
      if (visible(x3, y3)) activeStream.point(x3, y3);
    }
    function polygonInside() {
      var winding = 0;
      for (var i = 0, n = polygon.length; i < n; ++i) {
        for (var ring2 = polygon[i], j = 1, m = ring2.length, point7 = ring2[0], a0, a1, b02 = point7[0], b12 = point7[1]; j < m; ++j) {
          a0 = b02, a1 = b12, point7 = ring2[j], b02 = point7[0], b12 = point7[1];
          if (a1 <= y12) {
            if (b12 > y12 && (b02 - a0) * (y12 - a1) > (b12 - a1) * (x06 - a0)) ++winding;
          } else {
            if (b12 <= y12 && (b02 - a0) * (y12 - a1) < (b12 - a1) * (x06 - a0)) --winding;
          }
        }
      }
      return winding;
    }
    function polygonStart() {
      activeStream = bufferStream, segments = [], polygon = [], clean = true;
    }
    function polygonEnd() {
      var startInside = polygonInside(), cleanInside = clean && startInside, visible2 = (segments = merge(segments)).length;
      if (cleanInside || visible2) {
        stream.polygonStart();
        if (cleanInside) {
          stream.lineStart();
          interpolate(null, null, 1, stream);
          stream.lineEnd();
        }
        if (visible2) {
          rejoin_default(segments, compareIntersection2, startInside, interpolate, stream);
        }
        stream.polygonEnd();
      }
      activeStream = stream, segments = polygon = ring = null;
    }
    function lineStart() {
      clipStream.point = linePoint;
      if (polygon) polygon.push(ring = []);
      first2 = true;
      v_ = false;
      x_ = y_ = NaN;
    }
    function lineEnd() {
      if (segments) {
        linePoint(x__, y__);
        if (v__ && v_) bufferStream.rejoin();
        segments.push(bufferStream.result());
      }
      clipStream.point = point6;
      if (v_) activeStream.lineEnd();
    }
    function linePoint(x3, y3) {
      var v2 = visible(x3, y3);
      if (polygon) ring.push([x3, y3]);
      if (first2) {
        x__ = x3, y__ = y3, v__ = v2;
        first2 = false;
        if (v2) {
          activeStream.lineStart();
          activeStream.point(x3, y3);
        }
      } else {
        if (v2 && v_) activeStream.point(x3, y3);
        else {
          var a2 = [x_ = Math.max(clipMin, Math.min(clipMax, x_)), y_ = Math.max(clipMin, Math.min(clipMax, y_))], b = [x3 = Math.max(clipMin, Math.min(clipMax, x3)), y3 = Math.max(clipMin, Math.min(clipMax, y3))];
          if (line_default(a2, b, x06, y06, x12, y12)) {
            if (!v_) {
              activeStream.lineStart();
              activeStream.point(a2[0], a2[1]);
            }
            activeStream.point(b[0], b[1]);
            if (!v2) activeStream.lineEnd();
            clean = false;
          } else if (v2) {
            activeStream.lineStart();
            activeStream.point(x3, y3);
            clean = false;
          }
        }
      }
      x_ = x3, y_ = y3, v_ = v2;
    }
    return clipStream;
  };
}

// node_modules/d3-geo/src/graticule.js
function graticuleX(y06, y12, dy) {
  var y3 = range(y06, y12 - epsilon7, dy).concat(y12);
  return function(x3) {
    return y3.map(function(y4) {
      return [x3, y4];
    });
  };
}
function graticuleY(x06, x12, dx) {
  var x3 = range(x06, x12 - epsilon7, dx).concat(x12);
  return function(y3) {
    return x3.map(function(x4) {
      return [x4, y3];
    });
  };
}
function graticule() {
  var x12, x06, X13, X03, y12, y06, Y13, Y03, dx = 10, dy = dx, DX = 90, DY = 360, x3, y3, X3, Y3, precision = 2.5;
  function graticule3() {
    return { type: "MultiLineString", coordinates: lines() };
  }
  function lines() {
    return range(ceil(X03 / DX) * DX, X13, DX).map(X3).concat(range(ceil(Y03 / DY) * DY, Y13, DY).map(Y3)).concat(range(ceil(x06 / dx) * dx, x12, dx).filter(function(x4) {
      return abs3(x4 % DX) > epsilon7;
    }).map(x3)).concat(range(ceil(y06 / dy) * dy, y12, dy).filter(function(y4) {
      return abs3(y4 % DY) > epsilon7;
    }).map(y3));
  }
  graticule3.lines = function() {
    return lines().map(function(coordinates) {
      return { type: "LineString", coordinates };
    });
  };
  graticule3.outline = function() {
    return {
      type: "Polygon",
      coordinates: [
        X3(X03).concat(
          Y3(Y13).slice(1),
          X3(X13).reverse().slice(1),
          Y3(Y03).reverse().slice(1)
        )
      ]
    };
  };
  graticule3.extent = function(_) {
    if (!arguments.length) return graticule3.extentMinor();
    return graticule3.extentMajor(_).extentMinor(_);
  };
  graticule3.extentMajor = function(_) {
    if (!arguments.length) return [[X03, Y03], [X13, Y13]];
    X03 = +_[0][0], X13 = +_[1][0];
    Y03 = +_[0][1], Y13 = +_[1][1];
    if (X03 > X13) _ = X03, X03 = X13, X13 = _;
    if (Y03 > Y13) _ = Y03, Y03 = Y13, Y13 = _;
    return graticule3.precision(precision);
  };
  graticule3.extentMinor = function(_) {
    if (!arguments.length) return [[x06, y06], [x12, y12]];
    x06 = +_[0][0], x12 = +_[1][0];
    y06 = +_[0][1], y12 = +_[1][1];
    if (x06 > x12) _ = x06, x06 = x12, x12 = _;
    if (y06 > y12) _ = y06, y06 = y12, y12 = _;
    return graticule3.precision(precision);
  };
  graticule3.step = function(_) {
    if (!arguments.length) return graticule3.stepMinor();
    return graticule3.stepMajor(_).stepMinor(_);
  };
  graticule3.stepMajor = function(_) {
    if (!arguments.length) return [DX, DY];
    DX = +_[0], DY = +_[1];
    return graticule3;
  };
  graticule3.stepMinor = function(_) {
    if (!arguments.length) return [dx, dy];
    dx = +_[0], dy = +_[1];
    return graticule3;
  };
  graticule3.precision = function(_) {
    if (!arguments.length) return precision;
    precision = +_;
    x3 = graticuleX(y06, y12, 90);
    y3 = graticuleY(x06, x12, precision);
    X3 = graticuleX(Y03, Y13, 90);
    Y3 = graticuleY(X03, X13, precision);
    return graticule3;
  };
  return graticule3.extentMajor([[-180, -90 + epsilon7], [180, 90 - epsilon7]]).extentMinor([[-180, -80 - epsilon7], [180, 80 + epsilon7]]);
}
function graticule10() {
  return graticule()();
}

// node_modules/d3-geo/src/identity.js
var identity_default3 = (x3) => x3;

// node_modules/d3-geo/src/path/area.js
var areaSum2 = new Adder();
var areaRingSum2 = new Adder();
var x00;
var y00;
var x02;
var y02;
var areaStream2 = {
  point: noop2,
  lineStart: noop2,
  lineEnd: noop2,
  polygonStart: function() {
    areaStream2.lineStart = areaRingStart;
    areaStream2.lineEnd = areaRingEnd;
  },
  polygonEnd: function() {
    areaStream2.lineStart = areaStream2.lineEnd = areaStream2.point = noop2;
    areaSum2.add(abs3(areaRingSum2));
    areaRingSum2 = new Adder();
  },
  result: function() {
    var area2 = areaSum2 / 2;
    areaSum2 = new Adder();
    return area2;
  }
};
function areaRingStart() {
  areaStream2.point = areaPointFirst;
}
function areaPointFirst(x3, y3) {
  areaStream2.point = areaPoint;
  x00 = x02 = x3, y00 = y02 = y3;
}
function areaPoint(x3, y3) {
  areaRingSum2.add(y02 * x3 - x02 * y3);
  x02 = x3, y02 = y3;
}
function areaRingEnd() {
  areaPoint(x00, y00);
}
var area_default2 = areaStream2;

// node_modules/d3-geo/src/path/bounds.js
var x03 = Infinity;
var y03 = x03;
var x1 = -x03;
var y1 = x1;
var boundsStream = {
  point: boundsPoint,
  lineStart: noop2,
  lineEnd: noop2,
  polygonStart: noop2,
  polygonEnd: noop2,
  result: function() {
    var bounds = [[x03, y03], [x1, y1]];
    x1 = y1 = -(y03 = x03 = Infinity);
    return bounds;
  }
};
function boundsPoint(x3, y3) {
  if (x3 < x03) x03 = x3;
  if (x3 > x1) x1 = x3;
  if (y3 < y03) y03 = y3;
  if (y3 > y1) y1 = y3;
}
var bounds_default = boundsStream;

// node_modules/d3-geo/src/path/centroid.js
var X02 = 0;
var Y02 = 0;
var Z02 = 0;
var X12 = 0;
var Y12 = 0;
var Z12 = 0;
var X22 = 0;
var Y22 = 0;
var Z22 = 0;
var x002;
var y002;
var x04;
var y04;
var centroidStream2 = {
  point: centroidPoint2,
  lineStart: centroidLineStart2,
  lineEnd: centroidLineEnd2,
  polygonStart: function() {
    centroidStream2.lineStart = centroidRingStart2;
    centroidStream2.lineEnd = centroidRingEnd2;
  },
  polygonEnd: function() {
    centroidStream2.point = centroidPoint2;
    centroidStream2.lineStart = centroidLineStart2;
    centroidStream2.lineEnd = centroidLineEnd2;
  },
  result: function() {
    var centroid2 = Z22 ? [X22 / Z22, Y22 / Z22] : Z12 ? [X12 / Z12, Y12 / Z12] : Z02 ? [X02 / Z02, Y02 / Z02] : [NaN, NaN];
    X02 = Y02 = Z02 = X12 = Y12 = Z12 = X22 = Y22 = Z22 = 0;
    return centroid2;
  }
};
function centroidPoint2(x3, y3) {
  X02 += x3;
  Y02 += y3;
  ++Z02;
}
function centroidLineStart2() {
  centroidStream2.point = centroidPointFirstLine;
}
function centroidPointFirstLine(x3, y3) {
  centroidStream2.point = centroidPointLine;
  centroidPoint2(x04 = x3, y04 = y3);
}
function centroidPointLine(x3, y3) {
  var dx = x3 - x04, dy = y3 - y04, z = sqrt(dx * dx + dy * dy);
  X12 += z * (x04 + x3) / 2;
  Y12 += z * (y04 + y3) / 2;
  Z12 += z;
  centroidPoint2(x04 = x3, y04 = y3);
}
function centroidLineEnd2() {
  centroidStream2.point = centroidPoint2;
}
function centroidRingStart2() {
  centroidStream2.point = centroidPointFirstRing;
}
function centroidRingEnd2() {
  centroidPointRing(x002, y002);
}
function centroidPointFirstRing(x3, y3) {
  centroidStream2.point = centroidPointRing;
  centroidPoint2(x002 = x04 = x3, y002 = y04 = y3);
}
function centroidPointRing(x3, y3) {
  var dx = x3 - x04, dy = y3 - y04, z = sqrt(dx * dx + dy * dy);
  X12 += z * (x04 + x3) / 2;
  Y12 += z * (y04 + y3) / 2;
  Z12 += z;
  z = y04 * x3 - x04 * y3;
  X22 += z * (x04 + x3);
  Y22 += z * (y04 + y3);
  Z22 += z * 3;
  centroidPoint2(x04 = x3, y04 = y3);
}
var centroid_default2 = centroidStream2;

// node_modules/d3-geo/src/path/context.js
function PathContext(context) {
  this._context = context;
}
PathContext.prototype = {
  _radius: 4.5,
  pointRadius: function(_) {
    return this._radius = _, this;
  },
  polygonStart: function() {
    this._line = 0;
  },
  polygonEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._point = 0;
  },
  lineEnd: function() {
    if (this._line === 0) this._context.closePath();
    this._point = NaN;
  },
  point: function(x3, y3) {
    switch (this._point) {
      case 0: {
        this._context.moveTo(x3, y3);
        this._point = 1;
        break;
      }
      case 1: {
        this._context.lineTo(x3, y3);
        break;
      }
      default: {
        this._context.moveTo(x3 + this._radius, y3);
        this._context.arc(x3, y3, this._radius, 0, tau5);
        break;
      }
    }
  },
  result: noop2
};

// node_modules/d3-geo/src/path/measure.js
var lengthSum = new Adder();
var lengthRing;
var x003;
var y003;
var x05;
var y05;
var lengthStream = {
  point: noop2,
  lineStart: function() {
    lengthStream.point = lengthPointFirst;
  },
  lineEnd: function() {
    if (lengthRing) lengthPoint(x003, y003);
    lengthStream.point = noop2;
  },
  polygonStart: function() {
    lengthRing = true;
  },
  polygonEnd: function() {
    lengthRing = null;
  },
  result: function() {
    var length3 = +lengthSum;
    lengthSum = new Adder();
    return length3;
  }
};
function lengthPointFirst(x3, y3) {
  lengthStream.point = lengthPoint;
  x003 = x05 = x3, y003 = y05 = y3;
}
function lengthPoint(x3, y3) {
  x05 -= x3, y05 -= y3;
  lengthSum.add(sqrt(x05 * x05 + y05 * y05));
  x05 = x3, y05 = y3;
}
var measure_default = lengthStream;

// node_modules/d3-geo/src/path/string.js
var cacheDigits;
var cacheAppend;
var cacheRadius;
var cacheCircle;
var PathString = class {
  constructor(digits) {
    this._append = digits == null ? append2 : appendRound2(digits);
    this._radius = 4.5;
    this._ = "";
  }
  pointRadius(_) {
    this._radius = +_;
    return this;
  }
  polygonStart() {
    this._line = 0;
  }
  polygonEnd() {
    this._line = NaN;
  }
  lineStart() {
    this._point = 0;
  }
  lineEnd() {
    if (this._line === 0) this._ += "Z";
    this._point = NaN;
  }
  point(x3, y3) {
    switch (this._point) {
      case 0: {
        this._append`M${x3},${y3}`;
        this._point = 1;
        break;
      }
      case 1: {
        this._append`L${x3},${y3}`;
        break;
      }
      default: {
        this._append`M${x3},${y3}`;
        if (this._radius !== cacheRadius || this._append !== cacheAppend) {
          const r = this._radius;
          const s2 = this._;
          this._ = "";
          this._append`m0,${r}a${r},${r} 0 1,1 0,${-2 * r}a${r},${r} 0 1,1 0,${2 * r}z`;
          cacheRadius = r;
          cacheAppend = this._append;
          cacheCircle = this._;
          this._ = s2;
        }
        this._ += cacheCircle;
        break;
      }
    }
  }
  result() {
    const result = this._;
    this._ = "";
    return result.length ? result : null;
  }
};
function append2(strings) {
  let i = 1;
  this._ += strings[0];
  for (const j = strings.length; i < j; ++i) {
    this._ += arguments[i] + strings[i];
  }
}
function appendRound2(digits) {
  const d = Math.floor(digits);
  if (!(d >= 0)) throw new RangeError(`invalid digits: ${digits}`);
  if (d > 15) return append2;
  if (d !== cacheDigits) {
    const k2 = 10 ** d;
    cacheDigits = d;
    cacheAppend = function append3(strings) {
      let i = 1;
      this._ += strings[0];
      for (const j = strings.length; i < j; ++i) {
        this._ += Math.round(arguments[i] * k2) / k2 + strings[i];
      }
    };
  }
  return cacheAppend;
}

// node_modules/d3-geo/src/path/index.js
function path_default(projection3, context) {
  let digits = 3, pointRadius = 4.5, projectionStream, contextStream;
  function path2(object) {
    if (object) {
      if (typeof pointRadius === "function") contextStream.pointRadius(+pointRadius.apply(this, arguments));
      stream_default(object, projectionStream(contextStream));
    }
    return contextStream.result();
  }
  path2.area = function(object) {
    stream_default(object, projectionStream(area_default2));
    return area_default2.result();
  };
  path2.measure = function(object) {
    stream_default(object, projectionStream(measure_default));
    return measure_default.result();
  };
  path2.bounds = function(object) {
    stream_default(object, projectionStream(bounds_default));
    return bounds_default.result();
  };
  path2.centroid = function(object) {
    stream_default(object, projectionStream(centroid_default2));
    return centroid_default2.result();
  };
  path2.projection = function(_) {
    if (!arguments.length) return projection3;
    projectionStream = _ == null ? (projection3 = null, identity_default3) : (projection3 = _).stream;
    return path2;
  };
  path2.context = function(_) {
    if (!arguments.length) return context;
    contextStream = _ == null ? (context = null, new PathString(digits)) : new PathContext(context = _);
    if (typeof pointRadius !== "function") contextStream.pointRadius(pointRadius);
    return path2;
  };
  path2.pointRadius = function(_) {
    if (!arguments.length) return pointRadius;
    pointRadius = typeof _ === "function" ? _ : (contextStream.pointRadius(+_), +_);
    return path2;
  };
  path2.digits = function(_) {
    if (!arguments.length) return digits;
    if (_ == null) digits = null;
    else {
      const d = Math.floor(_);
      if (!(d >= 0)) throw new RangeError(`invalid digits: ${_}`);
      digits = d;
    }
    if (context === null) contextStream = new PathString(digits);
    return path2;
  };
  return path2.projection(projection3).digits(digits).context(context);
}

// node_modules/d3-geo/src/transform.js
function transform_default(methods) {
  return {
    stream: transformer(methods)
  };
}
function transformer(methods) {
  return function(stream) {
    var s2 = new TransformStream();
    for (var key in methods) s2[key] = methods[key];
    s2.stream = stream;
    return s2;
  };
}
function TransformStream() {
}
TransformStream.prototype = {
  constructor: TransformStream,
  point: function(x3, y3) {
    this.stream.point(x3, y3);
  },
  sphere: function() {
    this.stream.sphere();
  },
  lineStart: function() {
    this.stream.lineStart();
  },
  lineEnd: function() {
    this.stream.lineEnd();
  },
  polygonStart: function() {
    this.stream.polygonStart();
  },
  polygonEnd: function() {
    this.stream.polygonEnd();
  }
};

// node_modules/d3-geo/src/projection/fit.js
function fit(projection3, fitBounds, object) {
  var clip = projection3.clipExtent && projection3.clipExtent();
  projection3.scale(150).translate([0, 0]);
  if (clip != null) projection3.clipExtent(null);
  stream_default(object, projection3.stream(bounds_default));
  fitBounds(bounds_default.result());
  if (clip != null) projection3.clipExtent(clip);
  return projection3;
}
function fitExtent(projection3, extent3, object) {
  return fit(projection3, function(b) {
    var w = extent3[1][0] - extent3[0][0], h = extent3[1][1] - extent3[0][1], k2 = Math.min(w / (b[1][0] - b[0][0]), h / (b[1][1] - b[0][1])), x3 = +extent3[0][0] + (w - k2 * (b[1][0] + b[0][0])) / 2, y3 = +extent3[0][1] + (h - k2 * (b[1][1] + b[0][1])) / 2;
    projection3.scale(150 * k2).translate([x3, y3]);
  }, object);
}
function fitSize(projection3, size, object) {
  return fitExtent(projection3, [[0, 0], size], object);
}
function fitWidth(projection3, width, object) {
  return fit(projection3, function(b) {
    var w = +width, k2 = w / (b[1][0] - b[0][0]), x3 = (w - k2 * (b[1][0] + b[0][0])) / 2, y3 = -k2 * b[0][1];
    projection3.scale(150 * k2).translate([x3, y3]);
  }, object);
}
function fitHeight(projection3, height, object) {
  return fit(projection3, function(b) {
    var h = +height, k2 = h / (b[1][1] - b[0][1]), x3 = -k2 * b[0][0], y3 = (h - k2 * (b[1][1] + b[0][1])) / 2;
    projection3.scale(150 * k2).translate([x3, y3]);
  }, object);
}

// node_modules/d3-geo/src/projection/resample.js
var maxDepth = 16;
var cosMinDistance = cos2(30 * radians2);
function resample_default(project2, delta2) {
  return +delta2 ? resample(project2, delta2) : resampleNone(project2);
}
function resampleNone(project2) {
  return transformer({
    point: function(x3, y3) {
      x3 = project2(x3, y3);
      this.stream.point(x3[0], x3[1]);
    }
  });
}
function resample(project2, delta2) {
  function resampleLineTo(x06, y06, lambda0, a0, b02, c0, x12, y12, lambda1, a1, b12, c1, depth, stream) {
    var dx = x12 - x06, dy = y12 - y06, d2 = dx * dx + dy * dy;
    if (d2 > 4 * delta2 && depth--) {
      var a2 = a0 + a1, b = b02 + b12, c4 = c0 + c1, m = sqrt(a2 * a2 + b * b + c4 * c4), phi2 = asin(c4 /= m), lambda2 = abs3(abs3(c4) - 1) < epsilon7 || abs3(lambda0 - lambda1) < epsilon7 ? (lambda0 + lambda1) / 2 : atan2(b, a2), p = project2(lambda2, phi2), x22 = p[0], y22 = p[1], dx2 = x22 - x06, dy2 = y22 - y06, dz = dy * dx2 - dx * dy2;
      if (dz * dz / d2 > delta2 || abs3((dx * dx2 + dy * dy2) / d2 - 0.5) > 0.3 || a0 * a1 + b02 * b12 + c0 * c1 < cosMinDistance) {
        resampleLineTo(x06, y06, lambda0, a0, b02, c0, x22, y22, lambda2, a2 /= m, b /= m, c4, depth, stream);
        stream.point(x22, y22);
        resampleLineTo(x22, y22, lambda2, a2, b, c4, x12, y12, lambda1, a1, b12, c1, depth, stream);
      }
    }
  }
  return function(stream) {
    var lambda002, x004, y004, a00, b00, c00, lambda0, x06, y06, a0, b02, c0;
    var resampleStream = {
      point: point6,
      lineStart,
      lineEnd,
      polygonStart: function() {
        stream.polygonStart();
        resampleStream.lineStart = ringStart;
      },
      polygonEnd: function() {
        stream.polygonEnd();
        resampleStream.lineStart = lineStart;
      }
    };
    function point6(x3, y3) {
      x3 = project2(x3, y3);
      stream.point(x3[0], x3[1]);
    }
    function lineStart() {
      x06 = NaN;
      resampleStream.point = linePoint;
      stream.lineStart();
    }
    function linePoint(lambda, phi2) {
      var c4 = cartesian([lambda, phi2]), p = project2(lambda, phi2);
      resampleLineTo(x06, y06, lambda0, a0, b02, c0, x06 = p[0], y06 = p[1], lambda0 = lambda, a0 = c4[0], b02 = c4[1], c0 = c4[2], maxDepth, stream);
      stream.point(x06, y06);
    }
    function lineEnd() {
      resampleStream.point = point6;
      stream.lineEnd();
    }
    function ringStart() {
      lineStart();
      resampleStream.point = ringPoint;
      resampleStream.lineEnd = ringEnd;
    }
    function ringPoint(lambda, phi2) {
      linePoint(lambda002 = lambda, phi2), x004 = x06, y004 = y06, a00 = a0, b00 = b02, c00 = c0;
      resampleStream.point = linePoint;
    }
    function ringEnd() {
      resampleLineTo(x06, y06, lambda0, a0, b02, c0, x004, y004, lambda002, a00, b00, c00, maxDepth, stream);
      resampleStream.lineEnd = lineEnd;
      lineEnd();
    }
    return resampleStream;
  };
}

// node_modules/d3-geo/src/projection/index.js
var transformRadians = transformer({
  point: function(x3, y3) {
    this.stream.point(x3 * radians2, y3 * radians2);
  }
});
function transformRotate(rotate) {
  return transformer({
    point: function(x3, y3) {
      var r = rotate(x3, y3);
      return this.stream.point(r[0], r[1]);
    }
  });
}
function scaleTranslate(k2, dx, dy, sx, sy) {
  function transform2(x3, y3) {
    x3 *= sx;
    y3 *= sy;
    return [dx + k2 * x3, dy - k2 * y3];
  }
  transform2.invert = function(x3, y3) {
    return [(x3 - dx) / k2 * sx, (dy - y3) / k2 * sy];
  };
  return transform2;
}
function scaleTranslateRotate(k2, dx, dy, sx, sy, alpha) {
  if (!alpha) return scaleTranslate(k2, dx, dy, sx, sy);
  var cosAlpha = cos2(alpha), sinAlpha = sin2(alpha), a2 = cosAlpha * k2, b = sinAlpha * k2, ai = cosAlpha / k2, bi = sinAlpha / k2, ci = (sinAlpha * dy - cosAlpha * dx) / k2, fi = (sinAlpha * dx + cosAlpha * dy) / k2;
  function transform2(x3, y3) {
    x3 *= sx;
    y3 *= sy;
    return [a2 * x3 - b * y3 + dx, dy - b * x3 - a2 * y3];
  }
  transform2.invert = function(x3, y3) {
    return [sx * (ai * x3 - bi * y3 + ci), sy * (fi - bi * x3 - ai * y3)];
  };
  return transform2;
}
function projection(project2) {
  return projectionMutator(function() {
    return project2;
  })();
}
function projectionMutator(projectAt) {
  var project2, k2 = 150, x3 = 480, y3 = 250, lambda = 0, phi2 = 0, deltaLambda = 0, deltaPhi = 0, deltaGamma = 0, rotate, alpha = 0, sx = 1, sy = 1, theta = null, preclip = antimeridian_default, x06 = null, y06, x12, y12, postclip = identity_default3, delta2 = 0.5, projectResample, projectTransform, projectRotateTransform, cache, cacheStream;
  function projection3(point6) {
    return projectRotateTransform(point6[0] * radians2, point6[1] * radians2);
  }
  function invert(point6) {
    point6 = projectRotateTransform.invert(point6[0], point6[1]);
    return point6 && [point6[0] * degrees3, point6[1] * degrees3];
  }
  projection3.stream = function(stream) {
    return cache && cacheStream === stream ? cache : cache = transformRadians(transformRotate(rotate)(preclip(projectResample(postclip(cacheStream = stream)))));
  };
  projection3.preclip = function(_) {
    return arguments.length ? (preclip = _, theta = void 0, reset()) : preclip;
  };
  projection3.postclip = function(_) {
    return arguments.length ? (postclip = _, x06 = y06 = x12 = y12 = null, reset()) : postclip;
  };
  projection3.clipAngle = function(_) {
    return arguments.length ? (preclip = +_ ? circle_default(theta = _ * radians2) : (theta = null, antimeridian_default), reset()) : theta * degrees3;
  };
  projection3.clipExtent = function(_) {
    return arguments.length ? (postclip = _ == null ? (x06 = y06 = x12 = y12 = null, identity_default3) : clipRectangle(x06 = +_[0][0], y06 = +_[0][1], x12 = +_[1][0], y12 = +_[1][1]), reset()) : x06 == null ? null : [[x06, y06], [x12, y12]];
  };
  projection3.scale = function(_) {
    return arguments.length ? (k2 = +_, recenter()) : k2;
  };
  projection3.translate = function(_) {
    return arguments.length ? (x3 = +_[0], y3 = +_[1], recenter()) : [x3, y3];
  };
  projection3.center = function(_) {
    return arguments.length ? (lambda = _[0] % 360 * radians2, phi2 = _[1] % 360 * radians2, recenter()) : [lambda * degrees3, phi2 * degrees3];
  };
  projection3.rotate = function(_) {
    return arguments.length ? (deltaLambda = _[0] % 360 * radians2, deltaPhi = _[1] % 360 * radians2, deltaGamma = _.length > 2 ? _[2] % 360 * radians2 : 0, recenter()) : [deltaLambda * degrees3, deltaPhi * degrees3, deltaGamma * degrees3];
  };
  projection3.angle = function(_) {
    return arguments.length ? (alpha = _ % 360 * radians2, recenter()) : alpha * degrees3;
  };
  projection3.reflectX = function(_) {
    return arguments.length ? (sx = _ ? -1 : 1, recenter()) : sx < 0;
  };
  projection3.reflectY = function(_) {
    return arguments.length ? (sy = _ ? -1 : 1, recenter()) : sy < 0;
  };
  projection3.precision = function(_) {
    return arguments.length ? (projectResample = resample_default(projectTransform, delta2 = _ * _), reset()) : sqrt(delta2);
  };
  projection3.fitExtent = function(extent3, object) {
    return fitExtent(projection3, extent3, object);
  };
  projection3.fitSize = function(size, object) {
    return fitSize(projection3, size, object);
  };
  projection3.fitWidth = function(width, object) {
    return fitWidth(projection3, width, object);
  };
  projection3.fitHeight = function(height, object) {
    return fitHeight(projection3, height, object);
  };
  function recenter() {
    var center2 = scaleTranslateRotate(k2, 0, 0, sx, sy, alpha).apply(null, project2(lambda, phi2)), transform2 = scaleTranslateRotate(k2, x3 - center2[0], y3 - center2[1], sx, sy, alpha);
    rotate = rotateRadians(deltaLambda, deltaPhi, deltaGamma);
    projectTransform = compose_default(project2, transform2);
    projectRotateTransform = compose_default(rotate, projectTransform);
    projectResample = resample_default(projectTransform, delta2);
    return reset();
  }
  function reset() {
    cache = cacheStream = null;
    return projection3;
  }
  return function() {
    project2 = projectAt.apply(this, arguments);
    projection3.invert = project2.invert && invert;
    return recenter();
  };
}

// node_modules/d3-geo/src/projection/conic.js
function conicProjection(projectAt) {
  var phi0 = 0, phi1 = pi4 / 3, m = projectionMutator(projectAt), p = m(phi0, phi1);
  p.parallels = function(_) {
    return arguments.length ? m(phi0 = _[0] * radians2, phi1 = _[1] * radians2) : [phi0 * degrees3, phi1 * degrees3];
  };
  return p;
}

// node_modules/d3-geo/src/projection/cylindricalEqualArea.js
function cylindricalEqualAreaRaw(phi0) {
  var cosPhi0 = cos2(phi0);
  function forward(lambda, phi2) {
    return [lambda * cosPhi0, sin2(phi2) / cosPhi0];
  }
  forward.invert = function(x3, y3) {
    return [x3 / cosPhi0, asin(y3 * cosPhi0)];
  };
  return forward;
}

// node_modules/d3-geo/src/projection/conicEqualArea.js
function conicEqualAreaRaw(y06, y12) {
  var sy0 = sin2(y06), n = (sy0 + sin2(y12)) / 2;
  if (abs3(n) < epsilon7) return cylindricalEqualAreaRaw(y06);
  var c4 = 1 + sy0 * (2 * n - sy0), r0 = sqrt(c4) / n;
  function project2(x3, y3) {
    var r = sqrt(c4 - 2 * n * sin2(y3)) / n;
    return [r * sin2(x3 *= n), r0 - r * cos2(x3)];
  }
  project2.invert = function(x3, y3) {
    var r0y = r0 - y3, l = atan2(x3, abs3(r0y)) * sign(r0y);
    if (r0y * n < 0)
      l -= pi4 * sign(x3) * sign(r0y);
    return [l / n, asin((c4 - (x3 * x3 + r0y * r0y) * n * n) / (2 * n))];
  };
  return project2;
}
function conicEqualArea_default() {
  return conicProjection(conicEqualAreaRaw).scale(155.424).center([0, 33.6442]);
}

// node_modules/d3-geo/src/projection/albers.js
function albers_default() {
  return conicEqualArea_default().parallels([29.5, 45.5]).scale(1070).translate([480, 250]).rotate([96, 0]).center([-0.6, 38.7]);
}

// node_modules/d3-geo/src/projection/albersUsa.js
function multiplex(streams) {
  var n = streams.length;
  return {
    point: function(x3, y3) {
      var i = -1;
      while (++i < n) streams[i].point(x3, y3);
    },
    sphere: function() {
      var i = -1;
      while (++i < n) streams[i].sphere();
    },
    lineStart: function() {
      var i = -1;
      while (++i < n) streams[i].lineStart();
    },
    lineEnd: function() {
      var i = -1;
      while (++i < n) streams[i].lineEnd();
    },
    polygonStart: function() {
      var i = -1;
      while (++i < n) streams[i].polygonStart();
    },
    polygonEnd: function() {
      var i = -1;
      while (++i < n) streams[i].polygonEnd();
    }
  };
}
function albersUsa_default() {
  var cache, cacheStream, lower48 = albers_default(), lower48Point, alaska = conicEqualArea_default().rotate([154, 0]).center([-2, 58.5]).parallels([55, 65]), alaskaPoint, hawaii = conicEqualArea_default().rotate([157, 0]).center([-3, 19.9]).parallels([8, 18]), hawaiiPoint, point6, pointStream = { point: function(x3, y3) {
    point6 = [x3, y3];
  } };
  function albersUsa(coordinates) {
    var x3 = coordinates[0], y3 = coordinates[1];
    return point6 = null, (lower48Point.point(x3, y3), point6) || (alaskaPoint.point(x3, y3), point6) || (hawaiiPoint.point(x3, y3), point6);
  }
  albersUsa.invert = function(coordinates) {
    var k2 = lower48.scale(), t = lower48.translate(), x3 = (coordinates[0] - t[0]) / k2, y3 = (coordinates[1] - t[1]) / k2;
    return (y3 >= 0.12 && y3 < 0.234 && x3 >= -0.425 && x3 < -0.214 ? alaska : y3 >= 0.166 && y3 < 0.234 && x3 >= -0.214 && x3 < -0.115 ? hawaii : lower48).invert(coordinates);
  };
  albersUsa.stream = function(stream) {
    return cache && cacheStream === stream ? cache : cache = multiplex([lower48.stream(cacheStream = stream), alaska.stream(stream), hawaii.stream(stream)]);
  };
  albersUsa.precision = function(_) {
    if (!arguments.length) return lower48.precision();
    lower48.precision(_), alaska.precision(_), hawaii.precision(_);
    return reset();
  };
  albersUsa.scale = function(_) {
    if (!arguments.length) return lower48.scale();
    lower48.scale(_), alaska.scale(_ * 0.35), hawaii.scale(_);
    return albersUsa.translate(lower48.translate());
  };
  albersUsa.translate = function(_) {
    if (!arguments.length) return lower48.translate();
    var k2 = lower48.scale(), x3 = +_[0], y3 = +_[1];
    lower48Point = lower48.translate(_).clipExtent([[x3 - 0.455 * k2, y3 - 0.238 * k2], [x3 + 0.455 * k2, y3 + 0.238 * k2]]).stream(pointStream);
    alaskaPoint = alaska.translate([x3 - 0.307 * k2, y3 + 0.201 * k2]).clipExtent([[x3 - 0.425 * k2 + epsilon7, y3 + 0.12 * k2 + epsilon7], [x3 - 0.214 * k2 - epsilon7, y3 + 0.234 * k2 - epsilon7]]).stream(pointStream);
    hawaiiPoint = hawaii.translate([x3 - 0.205 * k2, y3 + 0.212 * k2]).clipExtent([[x3 - 0.214 * k2 + epsilon7, y3 + 0.166 * k2 + epsilon7], [x3 - 0.115 * k2 - epsilon7, y3 + 0.234 * k2 - epsilon7]]).stream(pointStream);
    return reset();
  };
  albersUsa.fitExtent = function(extent3, object) {
    return fitExtent(albersUsa, extent3, object);
  };
  albersUsa.fitSize = function(size, object) {
    return fitSize(albersUsa, size, object);
  };
  albersUsa.fitWidth = function(width, object) {
    return fitWidth(albersUsa, width, object);
  };
  albersUsa.fitHeight = function(height, object) {
    return fitHeight(albersUsa, height, object);
  };
  function reset() {
    cache = cacheStream = null;
    return albersUsa;
  }
  return albersUsa.scale(1070);
}

// node_modules/d3-geo/src/projection/azimuthal.js
function azimuthalRaw(scale3) {
  return function(x3, y3) {
    var cx = cos2(x3), cy = cos2(y3), k2 = scale3(cx * cy);
    if (k2 === Infinity) return [2, 0];
    return [
      k2 * cy * sin2(x3),
      k2 * sin2(y3)
    ];
  };
}
function azimuthalInvert(angle) {
  return function(x3, y3) {
    var z = sqrt(x3 * x3 + y3 * y3), c4 = angle(z), sc = sin2(c4), cc2 = cos2(c4);
    return [
      atan2(x3 * sc, z * cc2),
      asin(z && y3 * sc / z)
    ];
  };
}

// node_modules/d3-geo/src/projection/azimuthalEqualArea.js
var azimuthalEqualAreaRaw = azimuthalRaw(function(cxcy) {
  return sqrt(2 / (1 + cxcy));
});
azimuthalEqualAreaRaw.invert = azimuthalInvert(function(z) {
  return 2 * asin(z / 2);
});
function azimuthalEqualArea_default() {
  return projection(azimuthalEqualAreaRaw).scale(124.75).clipAngle(180 - 1e-3);
}

// node_modules/d3-geo/src/projection/azimuthalEquidistant.js
var azimuthalEquidistantRaw = azimuthalRaw(function(c4) {
  return (c4 = acos(c4)) && c4 / sin2(c4);
});
azimuthalEquidistantRaw.invert = azimuthalInvert(function(z) {
  return z;
});
function azimuthalEquidistant_default() {
  return projection(azimuthalEquidistantRaw).scale(79.4188).clipAngle(180 - 1e-3);
}

// node_modules/d3-geo/src/projection/mercator.js
function mercatorRaw(lambda, phi2) {
  return [lambda, log(tan((halfPi3 + phi2) / 2))];
}
mercatorRaw.invert = function(x3, y3) {
  return [x3, 2 * atan(exp(y3)) - halfPi3];
};
function mercator_default() {
  return mercatorProjection(mercatorRaw).scale(961 / tau5);
}
function mercatorProjection(project2) {
  var m = projection(project2), center2 = m.center, scale3 = m.scale, translate = m.translate, clipExtent = m.clipExtent, x06 = null, y06, x12, y12;
  m.scale = function(_) {
    return arguments.length ? (scale3(_), reclip()) : scale3();
  };
  m.translate = function(_) {
    return arguments.length ? (translate(_), reclip()) : translate();
  };
  m.center = function(_) {
    return arguments.length ? (center2(_), reclip()) : center2();
  };
  m.clipExtent = function(_) {
    return arguments.length ? (_ == null ? x06 = y06 = x12 = y12 = null : (x06 = +_[0][0], y06 = +_[0][1], x12 = +_[1][0], y12 = +_[1][1]), reclip()) : x06 == null ? null : [[x06, y06], [x12, y12]];
  };
  function reclip() {
    var k2 = pi4 * scale3(), t = m(rotation_default(m.rotate()).invert([0, 0]));
    return clipExtent(x06 == null ? [[t[0] - k2, t[1] - k2], [t[0] + k2, t[1] + k2]] : project2 === mercatorRaw ? [[Math.max(t[0] - k2, x06), y06], [Math.min(t[0] + k2, x12), y12]] : [[x06, Math.max(t[1] - k2, y06)], [x12, Math.min(t[1] + k2, y12)]]);
  }
  return reclip();
}

// node_modules/d3-geo/src/projection/conicConformal.js
function tany(y3) {
  return tan((halfPi3 + y3) / 2);
}
function conicConformalRaw(y06, y12) {
  var cy0 = cos2(y06), n = y06 === y12 ? sin2(y06) : log(cy0 / cos2(y12)) / log(tany(y12) / tany(y06)), f = cy0 * pow2(tany(y06), n) / n;
  if (!n) return mercatorRaw;
  function project2(x3, y3) {
    if (f > 0) {
      if (y3 < -halfPi3 + epsilon7) y3 = -halfPi3 + epsilon7;
    } else {
      if (y3 > halfPi3 - epsilon7) y3 = halfPi3 - epsilon7;
    }
    var r = f / pow2(tany(y3), n);
    return [r * sin2(n * x3), f - r * cos2(n * x3)];
  }
  project2.invert = function(x3, y3) {
    var fy = f - y3, r = sign(n) * sqrt(x3 * x3 + fy * fy), l = atan2(x3, abs3(fy)) * sign(fy);
    if (fy * n < 0)
      l -= pi4 * sign(x3) * sign(fy);
    return [l / n, 2 * atan(pow2(f / r, 1 / n)) - halfPi3];
  };
  return project2;
}
function conicConformal_default() {
  return conicProjection(conicConformalRaw).scale(109.5).parallels([30, 30]);
}

// node_modules/d3-geo/src/projection/equirectangular.js
function equirectangularRaw(lambda, phi2) {
  return [lambda, phi2];
}
equirectangularRaw.invert = equirectangularRaw;
function equirectangular_default() {
  return projection(equirectangularRaw).scale(152.63);
}

// node_modules/d3-geo/src/projection/conicEquidistant.js
function conicEquidistantRaw(y06, y12) {
  var cy0 = cos2(y06), n = y06 === y12 ? sin2(y06) : (cy0 - cos2(y12)) / (y12 - y06), g = cy0 / n + y06;
  if (abs3(n) < epsilon7) return equirectangularRaw;
  function project2(x3, y3) {
    var gy = g - y3, nx = n * x3;
    return [gy * sin2(nx), g - gy * cos2(nx)];
  }
  project2.invert = function(x3, y3) {
    var gy = g - y3, l = atan2(x3, abs3(gy)) * sign(gy);
    if (gy * n < 0)
      l -= pi4 * sign(x3) * sign(gy);
    return [l / n, g - sign(n) * sqrt(x3 * x3 + gy * gy)];
  };
  return project2;
}
function conicEquidistant_default() {
  return conicProjection(conicEquidistantRaw).scale(131.154).center([0, 13.9389]);
}

// node_modules/d3-geo/src/projection/equalEarth.js
var A1 = 1.340264;
var A2 = -0.081106;
var A3 = 893e-6;
var A4 = 3796e-6;
var M = sqrt(3) / 2;
var iterations = 12;
function equalEarthRaw(lambda, phi2) {
  var l = asin(M * sin2(phi2)), l2 = l * l, l6 = l2 * l2 * l2;
  return [
    lambda * cos2(l) / (M * (A1 + 3 * A2 * l2 + l6 * (7 * A3 + 9 * A4 * l2))),
    l * (A1 + A2 * l2 + l6 * (A3 + A4 * l2))
  ];
}
equalEarthRaw.invert = function(x3, y3) {
  var l = y3, l2 = l * l, l6 = l2 * l2 * l2;
  for (var i = 0, delta, fy, fpy; i < iterations; ++i) {
    fy = l * (A1 + A2 * l2 + l6 * (A3 + A4 * l2)) - y3;
    fpy = A1 + 3 * A2 * l2 + l6 * (7 * A3 + 9 * A4 * l2);
    l -= delta = fy / fpy, l2 = l * l, l6 = l2 * l2 * l2;
    if (abs3(delta) < epsilon22) break;
  }
  return [
    M * x3 * (A1 + 3 * A2 * l2 + l6 * (7 * A3 + 9 * A4 * l2)) / cos2(l),
    asin(sin2(l) / M)
  ];
};
function equalEarth_default() {
  return projection(equalEarthRaw).scale(177.158);
}

// node_modules/d3-geo/src/projection/gnomonic.js
function gnomonicRaw(x3, y3) {
  var cy = cos2(y3), k2 = cos2(x3) * cy;
  return [cy * sin2(x3) / k2, sin2(y3) / k2];
}
gnomonicRaw.invert = azimuthalInvert(atan);
function gnomonic_default() {
  return projection(gnomonicRaw).scale(144.049).clipAngle(60);
}

// node_modules/d3-geo/src/projection/naturalEarth1.js
function naturalEarth1Raw(lambda, phi2) {
  var phi22 = phi2 * phi2, phi4 = phi22 * phi22;
  return [
    lambda * (0.8707 - 0.131979 * phi22 + phi4 * (-0.013791 + phi4 * (3971e-6 * phi22 - 1529e-6 * phi4))),
    phi2 * (1.007226 + phi22 * (0.015085 + phi4 * (-0.044475 + 0.028874 * phi22 - 5916e-6 * phi4)))
  ];
}
naturalEarth1Raw.invert = function(x3, y3) {
  var phi2 = y3, i = 25, delta;
  do {
    var phi22 = phi2 * phi2, phi4 = phi22 * phi22;
    phi2 -= delta = (phi2 * (1.007226 + phi22 * (0.015085 + phi4 * (-0.044475 + 0.028874 * phi22 - 5916e-6 * phi4))) - y3) / (1.007226 + phi22 * (0.015085 * 3 + phi4 * (-0.044475 * 7 + 0.028874 * 9 * phi22 - 5916e-6 * 11 * phi4)));
  } while (abs3(delta) > epsilon7 && --i > 0);
  return [
    x3 / (0.8707 + (phi22 = phi2 * phi2) * (-0.131979 + phi22 * (-0.013791 + phi22 * phi22 * phi22 * (3971e-6 - 1529e-6 * phi22)))),
    phi2
  ];
};

// node_modules/d3-geo/src/projection/orthographic.js
function orthographicRaw(x3, y3) {
  return [cos2(y3) * sin2(x3), sin2(y3)];
}
orthographicRaw.invert = azimuthalInvert(asin);
function orthographic_default() {
  return projection(orthographicRaw).scale(249.5).clipAngle(90 + epsilon7);
}

// node_modules/d3-geo/src/projection/stereographic.js
function stereographicRaw(x3, y3) {
  var cy = cos2(y3), k2 = 1 + cos2(x3) * cy;
  return [cy * sin2(x3) / k2, sin2(y3) / k2];
}
stereographicRaw.invert = azimuthalInvert(function(z) {
  return 2 * atan(z);
});
function stereographic_default() {
  return projection(stereographicRaw).scale(250).clipAngle(142);
}

// node_modules/d3-geo/src/projection/transverseMercator.js
function transverseMercatorRaw(lambda, phi2) {
  return [log(tan((halfPi3 + phi2) / 2)), -lambda];
}
transverseMercatorRaw.invert = function(x3, y3) {
  return [-y3, 2 * atan(exp(x3)) - halfPi3];
};
function transverseMercator_default() {
  var m = mercatorProjection(transverseMercatorRaw), center2 = m.center, rotate = m.rotate;
  m.center = function(_) {
    return arguments.length ? center2([-_[1], _[0]]) : (_ = center2(), [_[1], -_[0]]);
  };
  m.rotate = function(_) {
    return arguments.length ? rotate([_[0], _[1], _.length > 2 ? _[2] + 90 : 90]) : (_ = rotate(), [_[0], _[1], _[2] - 90]);
  };
  return rotate([0, 0, 90]).scale(159.155);
}

// node_modules/d3-hierarchy/src/cluster.js
function defaultSeparation(a2, b) {
  return a2.parent === b.parent ? 1 : 2;
}
function meanX(children2) {
  return children2.reduce(meanXReduce, 0) / children2.length;
}
function meanXReduce(x3, c4) {
  return x3 + c4.x;
}
function maxY(children2) {
  return 1 + children2.reduce(maxYReduce, 0);
}
function maxYReduce(y3, c4) {
  return Math.max(y3, c4.y);
}
function leafLeft(node) {
  var children2;
  while (children2 = node.children) node = children2[0];
  return node;
}
function leafRight(node) {
  var children2;
  while (children2 = node.children) node = children2[children2.length - 1];
  return node;
}
function cluster_default() {
  var separation = defaultSeparation, dx = 1, dy = 1, nodeSize = false;
  function cluster2(root2) {
    var previousNode, x3 = 0;
    root2.eachAfter(function(node) {
      var children2 = node.children;
      if (children2) {
        node.x = meanX(children2);
        node.y = maxY(children2);
      } else {
        node.x = previousNode ? x3 += separation(node, previousNode) : 0;
        node.y = 0;
        previousNode = node;
      }
    });
    var left2 = leafLeft(root2), right2 = leafRight(root2), x06 = left2.x - separation(left2, right2) / 2, x12 = right2.x + separation(right2, left2) / 2;
    return root2.eachAfter(nodeSize ? function(node) {
      node.x = (node.x - root2.x) * dx;
      node.y = (root2.y - node.y) * dy;
    } : function(node) {
      node.x = (node.x - x06) / (x12 - x06) * dx;
      node.y = (1 - (root2.y ? node.y / root2.y : 1)) * dy;
    });
  }
  cluster2.separation = function(x3) {
    return arguments.length ? (separation = x3, cluster2) : separation;
  };
  cluster2.size = function(x3) {
    return arguments.length ? (nodeSize = false, dx = +x3[0], dy = +x3[1], cluster2) : nodeSize ? null : [dx, dy];
  };
  cluster2.nodeSize = function(x3) {
    return arguments.length ? (nodeSize = true, dx = +x3[0], dy = +x3[1], cluster2) : nodeSize ? [dx, dy] : null;
  };
  return cluster2;
}

// node_modules/d3-hierarchy/src/hierarchy/count.js
function count2(node) {
  var sum4 = 0, children2 = node.children, i = children2 && children2.length;
  if (!i) sum4 = 1;
  else while (--i >= 0) sum4 += children2[i].value;
  node.value = sum4;
}
function count_default() {
  return this.eachAfter(count2);
}

// node_modules/d3-hierarchy/src/hierarchy/each.js
function each_default2(callback, that) {
  let index2 = -1;
  for (const node of this) {
    callback.call(that, node, ++index2, this);
  }
  return this;
}

// node_modules/d3-hierarchy/src/hierarchy/eachBefore.js
function eachBefore_default(callback, that) {
  var node = this, nodes = [node], children2, i, index2 = -1;
  while (node = nodes.pop()) {
    callback.call(that, node, ++index2, this);
    if (children2 = node.children) {
      for (i = children2.length - 1; i >= 0; --i) {
        nodes.push(children2[i]);
      }
    }
  }
  return this;
}

// node_modules/d3-hierarchy/src/hierarchy/eachAfter.js
function eachAfter_default(callback, that) {
  var node = this, nodes = [node], next = [], children2, i, n, index2 = -1;
  while (node = nodes.pop()) {
    next.push(node);
    if (children2 = node.children) {
      for (i = 0, n = children2.length; i < n; ++i) {
        nodes.push(children2[i]);
      }
    }
  }
  while (node = next.pop()) {
    callback.call(that, node, ++index2, this);
  }
  return this;
}

// node_modules/d3-hierarchy/src/hierarchy/find.js
function find_default2(callback, that) {
  let index2 = -1;
  for (const node of this) {
    if (callback.call(that, node, ++index2, this)) {
      return node;
    }
  }
}

// node_modules/d3-hierarchy/src/hierarchy/sum.js
function sum_default(value) {
  return this.eachAfter(function(node) {
    var sum4 = +value(node.data) || 0, children2 = node.children, i = children2 && children2.length;
    while (--i >= 0) sum4 += children2[i].value;
    node.value = sum4;
  });
}

// node_modules/d3-hierarchy/src/hierarchy/sort.js
function sort_default2(compare) {
  return this.eachBefore(function(node) {
    if (node.children) {
      node.children.sort(compare);
    }
  });
}

// node_modules/d3-hierarchy/src/hierarchy/path.js
function path_default2(end) {
  var start2 = this, ancestor = leastCommonAncestor(start2, end), nodes = [start2];
  while (start2 !== ancestor) {
    start2 = start2.parent;
    nodes.push(start2);
  }
  var k2 = nodes.length;
  while (end !== ancestor) {
    nodes.splice(k2, 0, end);
    end = end.parent;
  }
  return nodes;
}
function leastCommonAncestor(a2, b) {
  if (a2 === b) return a2;
  var aNodes = a2.ancestors(), bNodes = b.ancestors(), c4 = null;
  a2 = aNodes.pop();
  b = bNodes.pop();
  while (a2 === b) {
    c4 = a2;
    a2 = aNodes.pop();
    b = bNodes.pop();
  }
  return c4;
}

// node_modules/d3-hierarchy/src/hierarchy/ancestors.js
function ancestors_default() {
  var node = this, nodes = [node];
  while (node = node.parent) {
    nodes.push(node);
  }
  return nodes;
}

// node_modules/d3-hierarchy/src/hierarchy/descendants.js
function descendants_default() {
  return Array.from(this);
}

// node_modules/d3-hierarchy/src/hierarchy/leaves.js
function leaves_default() {
  var leaves = [];
  this.eachBefore(function(node) {
    if (!node.children) {
      leaves.push(node);
    }
  });
  return leaves;
}

// node_modules/d3-hierarchy/src/hierarchy/links.js
function links_default() {
  var root2 = this, links = [];
  root2.each(function(node) {
    if (node !== root2) {
      links.push({ source: node.parent, target: node });
    }
  });
  return links;
}

// node_modules/d3-hierarchy/src/hierarchy/iterator.js
function* iterator_default2() {
  var node = this, current, next = [node], children2, i, n;
  do {
    current = next.reverse(), next = [];
    while (node = current.pop()) {
      yield node;
      if (children2 = node.children) {
        for (i = 0, n = children2.length; i < n; ++i) {
          next.push(children2[i]);
        }
      }
    }
  } while (next.length);
}

// node_modules/d3-hierarchy/src/hierarchy/index.js
function hierarchy(data, children2) {
  if (data instanceof Map) {
    data = [void 0, data];
    if (children2 === void 0) children2 = mapChildren;
  } else if (children2 === void 0) {
    children2 = objectChildren;
  }
  var root2 = new Node(data), node, nodes = [root2], child, childs, i, n;
  while (node = nodes.pop()) {
    if ((childs = children2(node.data)) && (n = (childs = Array.from(childs)).length)) {
      node.children = childs;
      for (i = n - 1; i >= 0; --i) {
        nodes.push(child = childs[i] = new Node(childs[i]));
        child.parent = node;
        child.depth = node.depth + 1;
      }
    }
  }
  return root2.eachBefore(computeHeight);
}
function node_copy() {
  return hierarchy(this).eachBefore(copyData);
}
function objectChildren(d) {
  return d.children;
}
function mapChildren(d) {
  return Array.isArray(d) ? d[1] : null;
}
function copyData(node) {
  if (node.data.value !== void 0) node.value = node.data.value;
  node.data = node.data.data;
}
function computeHeight(node) {
  var height = 0;
  do
    node.height = height;
  while ((node = node.parent) && node.height < ++height);
}
function Node(data) {
  this.data = data;
  this.depth = this.height = 0;
  this.parent = null;
}
Node.prototype = hierarchy.prototype = {
  constructor: Node,
  count: count_default,
  each: each_default2,
  eachAfter: eachAfter_default,
  eachBefore: eachBefore_default,
  find: find_default2,
  sum: sum_default,
  sort: sort_default2,
  path: path_default2,
  ancestors: ancestors_default,
  descendants: descendants_default,
  leaves: leaves_default,
  links: links_default,
  copy: node_copy,
  [Symbol.iterator]: iterator_default2
};

// node_modules/d3-hierarchy/src/accessors.js
function optional(f) {
  return f == null ? null : required(f);
}
function required(f) {
  if (typeof f !== "function") throw new Error();
  return f;
}

// node_modules/d3-hierarchy/src/treemap/dice.js
function dice_default(parent, x06, y06, x12, y12) {
  var nodes = parent.children, node, i = -1, n = nodes.length, k2 = parent.value && (x12 - x06) / parent.value;
  while (++i < n) {
    node = nodes[i], node.y0 = y06, node.y1 = y12;
    node.x0 = x06, node.x1 = x06 += node.value * k2;
  }
}

// node_modules/d3-hierarchy/src/stratify.js
var preroot = { depth: -1 };
var ambiguous = {};
var imputed = {};
function defaultId(d) {
  return d.id;
}
function defaultParentId(d) {
  return d.parentId;
}
function stratify_default() {
  var id2 = defaultId, parentId = defaultParentId, path2;
  function stratify(data) {
    var nodes = Array.from(data), currentId = id2, currentParentId = parentId, n, d, i, root2, parent, node, nodeId, nodeKey, nodeByKey = /* @__PURE__ */ new Map();
    if (path2 != null) {
      const I = nodes.map((d2, i2) => normalize(path2(d2, i2, data)));
      const P = I.map(parentof);
      const S = new Set(I).add("");
      for (const i2 of P) {
        if (!S.has(i2)) {
          S.add(i2);
          I.push(i2);
          P.push(parentof(i2));
          nodes.push(imputed);
        }
      }
      currentId = (_, i2) => I[i2];
      currentParentId = (_, i2) => P[i2];
    }
    for (i = 0, n = nodes.length; i < n; ++i) {
      d = nodes[i], node = nodes[i] = new Node(d);
      if ((nodeId = currentId(d, i, data)) != null && (nodeId += "")) {
        nodeKey = node.id = nodeId;
        nodeByKey.set(nodeKey, nodeByKey.has(nodeKey) ? ambiguous : node);
      }
      if ((nodeId = currentParentId(d, i, data)) != null && (nodeId += "")) {
        node.parent = nodeId;
      }
    }
    for (i = 0; i < n; ++i) {
      node = nodes[i];
      if (nodeId = node.parent) {
        parent = nodeByKey.get(nodeId);
        if (!parent) throw new Error("missing: " + nodeId);
        if (parent === ambiguous) throw new Error("ambiguous: " + nodeId);
        if (parent.children) parent.children.push(node);
        else parent.children = [node];
        node.parent = parent;
      } else {
        if (root2) throw new Error("multiple roots");
        root2 = node;
      }
    }
    if (!root2) throw new Error("no root");
    if (path2 != null) {
      while (root2.data === imputed && root2.children.length === 1) {
        root2 = root2.children[0], --n;
      }
      for (let i2 = nodes.length - 1; i2 >= 0; --i2) {
        node = nodes[i2];
        if (node.data !== imputed) break;
        node.data = null;
      }
    }
    root2.parent = preroot;
    root2.eachBefore(function(node2) {
      node2.depth = node2.parent.depth + 1;
      --n;
    }).eachBefore(computeHeight);
    root2.parent = null;
    if (n > 0) throw new Error("cycle");
    return root2;
  }
  stratify.id = function(x3) {
    return arguments.length ? (id2 = optional(x3), stratify) : id2;
  };
  stratify.parentId = function(x3) {
    return arguments.length ? (parentId = optional(x3), stratify) : parentId;
  };
  stratify.path = function(x3) {
    return arguments.length ? (path2 = optional(x3), stratify) : path2;
  };
  return stratify;
}
function normalize(path2) {
  path2 = `${path2}`;
  let i = path2.length;
  if (slash(path2, i - 1) && !slash(path2, i - 2)) path2 = path2.slice(0, -1);
  return path2[0] === "/" ? path2 : `/${path2}`;
}
function parentof(path2) {
  let i = path2.length;
  if (i < 2) return "";
  while (--i > 1) if (slash(path2, i)) break;
  return path2.slice(0, i);
}
function slash(path2, i) {
  if (path2[i] === "/") {
    let k2 = 0;
    while (i > 0 && path2[--i] === "\\") ++k2;
    if ((k2 & 1) === 0) return true;
  }
  return false;
}

// node_modules/d3-hierarchy/src/tree.js
function defaultSeparation2(a2, b) {
  return a2.parent === b.parent ? 1 : 2;
}
function nextLeft(v2) {
  var children2 = v2.children;
  return children2 ? children2[0] : v2.t;
}
function nextRight(v2) {
  var children2 = v2.children;
  return children2 ? children2[children2.length - 1] : v2.t;
}
function moveSubtree(wm, wp, shift) {
  var change = shift / (wp.i - wm.i);
  wp.c -= change;
  wp.s += shift;
  wm.c += change;
  wp.z += shift;
  wp.m += shift;
}
function executeShifts(v2) {
  var shift = 0, change = 0, children2 = v2.children, i = children2.length, w;
  while (--i >= 0) {
    w = children2[i];
    w.z += shift;
    w.m += shift;
    shift += w.s + (change += w.c);
  }
}
function nextAncestor(vim, v2, ancestor) {
  return vim.a.parent === v2.parent ? vim.a : ancestor;
}
function TreeNode(node, i) {
  this._ = node;
  this.parent = null;
  this.children = null;
  this.A = null;
  this.a = this;
  this.z = 0;
  this.m = 0;
  this.c = 0;
  this.s = 0;
  this.t = null;
  this.i = i;
}
TreeNode.prototype = Object.create(Node.prototype);
function treeRoot(root2) {
  var tree2 = new TreeNode(root2, 0), node, nodes = [tree2], child, children2, i, n;
  while (node = nodes.pop()) {
    if (children2 = node._.children) {
      node.children = new Array(n = children2.length);
      for (i = n - 1; i >= 0; --i) {
        nodes.push(child = node.children[i] = new TreeNode(children2[i], i));
        child.parent = node;
      }
    }
  }
  (tree2.parent = new TreeNode(null, 0)).children = [tree2];
  return tree2;
}
function tree_default() {
  var separation = defaultSeparation2, dx = 1, dy = 1, nodeSize = null;
  function tree2(root2) {
    var t = treeRoot(root2);
    t.eachAfter(firstWalk), t.parent.m = -t.z;
    t.eachBefore(secondWalk);
    if (nodeSize) root2.eachBefore(sizeNode);
    else {
      var left2 = root2, right2 = root2, bottom2 = root2;
      root2.eachBefore(function(node) {
        if (node.x < left2.x) left2 = node;
        if (node.x > right2.x) right2 = node;
        if (node.depth > bottom2.depth) bottom2 = node;
      });
      var s2 = left2 === right2 ? 1 : separation(left2, right2) / 2, tx = s2 - left2.x, kx2 = dx / (right2.x + s2 + tx), ky2 = dy / (bottom2.depth || 1);
      root2.eachBefore(function(node) {
        node.x = (node.x + tx) * kx2;
        node.y = node.depth * ky2;
      });
    }
    return root2;
  }
  function firstWalk(v2) {
    var children2 = v2.children, siblings = v2.parent.children, w = v2.i ? siblings[v2.i - 1] : null;
    if (children2) {
      executeShifts(v2);
      var midpoint = (children2[0].z + children2[children2.length - 1].z) / 2;
      if (w) {
        v2.z = w.z + separation(v2._, w._);
        v2.m = v2.z - midpoint;
      } else {
        v2.z = midpoint;
      }
    } else if (w) {
      v2.z = w.z + separation(v2._, w._);
    }
    v2.parent.A = apportion(v2, w, v2.parent.A || siblings[0]);
  }
  function secondWalk(v2) {
    v2._.x = v2.z + v2.parent.m;
    v2.m += v2.parent.m;
  }
  function apportion(v2, w, ancestor) {
    if (w) {
      var vip = v2, vop = v2, vim = w, vom = vip.parent.children[0], sip = vip.m, sop = vop.m, sim = vim.m, som = vom.m, shift;
      while (vim = nextRight(vim), vip = nextLeft(vip), vim && vip) {
        vom = nextLeft(vom);
        vop = nextRight(vop);
        vop.a = v2;
        shift = vim.z + sim - vip.z - sip + separation(vim._, vip._);
        if (shift > 0) {
          moveSubtree(nextAncestor(vim, v2, ancestor), v2, shift);
          sip += shift;
          sop += shift;
        }
        sim += vim.m;
        sip += vip.m;
        som += vom.m;
        sop += vop.m;
      }
      if (vim && !nextRight(vop)) {
        vop.t = vim;
        vop.m += sim - sop;
      }
      if (vip && !nextLeft(vom)) {
        vom.t = vip;
        vom.m += sip - som;
        ancestor = v2;
      }
    }
    return ancestor;
  }
  function sizeNode(node) {
    node.x *= dx;
    node.y = node.depth * dy;
  }
  tree2.separation = function(x3) {
    return arguments.length ? (separation = x3, tree2) : separation;
  };
  tree2.size = function(x3) {
    return arguments.length ? (nodeSize = false, dx = +x3[0], dy = +x3[1], tree2) : nodeSize ? null : [dx, dy];
  };
  tree2.nodeSize = function(x3) {
    return arguments.length ? (nodeSize = true, dx = +x3[0], dy = +x3[1], tree2) : nodeSize ? [dx, dy] : null;
  };
  return tree2;
}

// node_modules/d3-hierarchy/src/treemap/slice.js
function slice_default(parent, x06, y06, x12, y12) {
  var nodes = parent.children, node, i = -1, n = nodes.length, k2 = parent.value && (y12 - y06) / parent.value;
  while (++i < n) {
    node = nodes[i], node.x0 = x06, node.x1 = x12;
    node.y0 = y06, node.y1 = y06 += node.value * k2;
  }
}

// node_modules/d3-hierarchy/src/treemap/squarify.js
var phi = (1 + Math.sqrt(5)) / 2;
function squarifyRatio(ratio, parent, x06, y06, x12, y12) {
  var rows = [], nodes = parent.children, row, nodeValue, i0 = 0, i1 = 0, n = nodes.length, dx, dy, value = parent.value, sumValue, minValue, maxValue, newRatio, minRatio, alpha, beta;
  while (i0 < n) {
    dx = x12 - x06, dy = y12 - y06;
    do
      sumValue = nodes[i1++].value;
    while (!sumValue && i1 < n);
    minValue = maxValue = sumValue;
    alpha = Math.max(dy / dx, dx / dy) / (value * ratio);
    beta = sumValue * sumValue * alpha;
    minRatio = Math.max(maxValue / beta, beta / minValue);
    for (; i1 < n; ++i1) {
      sumValue += nodeValue = nodes[i1].value;
      if (nodeValue < minValue) minValue = nodeValue;
      if (nodeValue > maxValue) maxValue = nodeValue;
      beta = sumValue * sumValue * alpha;
      newRatio = Math.max(maxValue / beta, beta / minValue);
      if (newRatio > minRatio) {
        sumValue -= nodeValue;
        break;
      }
      minRatio = newRatio;
    }
    rows.push(row = { value: sumValue, dice: dx < dy, children: nodes.slice(i0, i1) });
    if (row.dice) dice_default(row, x06, y06, x12, value ? y06 += dy * sumValue / value : y12);
    else slice_default(row, x06, y06, value ? x06 += dx * sumValue / value : x12, y12);
    value -= sumValue, i0 = i1;
  }
  return rows;
}
var squarify_default = (function custom10(ratio) {
  function squarify(parent, x06, y06, x12, y12) {
    squarifyRatio(ratio, parent, x06, y06, x12, y12);
  }
  squarify.ratio = function(x3) {
    return custom10((x3 = +x3) > 1 ? x3 : 1);
  };
  return squarify;
})(phi);

// node_modules/d3-hierarchy/src/treemap/resquarify.js
var resquarify_default = (function custom11(ratio) {
  function resquarify(parent, x06, y06, x12, y12) {
    if ((rows = parent._squarify) && rows.ratio === ratio) {
      var rows, row, nodes, i, j = -1, n, m = rows.length, value = parent.value;
      while (++j < m) {
        row = rows[j], nodes = row.children;
        for (i = row.value = 0, n = nodes.length; i < n; ++i) row.value += nodes[i].value;
        if (row.dice) dice_default(row, x06, y06, x12, value ? y06 += (y12 - y06) * row.value / value : y12);
        else slice_default(row, x06, y06, value ? x06 += (x12 - x06) * row.value / value : x12, y12);
        value -= row.value;
      }
    } else {
      parent._squarify = rows = squarifyRatio(ratio, parent, x06, y06, x12, y12);
      rows.ratio = ratio;
    }
  }
  resquarify.ratio = function(x3) {
    return custom11((x3 = +x3) > 1 ? x3 : 1);
  };
  return resquarify;
})(phi);

// node_modules/d3-random/src/defaultSource.js
var defaultSource_default = Math.random;

// node_modules/d3-random/src/uniform.js
var uniform_default = (function sourceRandomUniform(source) {
  function randomUniform(min4, max5) {
    min4 = min4 == null ? 0 : +min4;
    max5 = max5 == null ? 1 : +max5;
    if (arguments.length === 1) max5 = min4, min4 = 0;
    else max5 -= min4;
    return function() {
      return source() * max5 + min4;
    };
  }
  randomUniform.source = sourceRandomUniform;
  return randomUniform;
})(defaultSource_default);

// node_modules/d3-random/src/int.js
var int_default = (function sourceRandomInt(source) {
  function randomInt(min4, max5) {
    if (arguments.length < 2) max5 = min4, min4 = 0;
    min4 = Math.floor(min4);
    max5 = Math.floor(max5) - min4;
    return function() {
      return Math.floor(source() * max5 + min4);
    };
  }
  randomInt.source = sourceRandomInt;
  return randomInt;
})(defaultSource_default);

// node_modules/d3-random/src/normal.js
var normal_default = (function sourceRandomNormal(source) {
  function randomNormal(mu, sigma) {
    var x3, r;
    mu = mu == null ? 0 : +mu;
    sigma = sigma == null ? 1 : +sigma;
    return function() {
      var y3;
      if (x3 != null) y3 = x3, x3 = null;
      else do {
        x3 = source() * 2 - 1;
        y3 = source() * 2 - 1;
        r = x3 * x3 + y3 * y3;
      } while (!r || r > 1);
      return mu + sigma * y3 * Math.sqrt(-2 * Math.log(r) / r);
    };
  }
  randomNormal.source = sourceRandomNormal;
  return randomNormal;
})(defaultSource_default);

// node_modules/d3-random/src/logNormal.js
var logNormal_default = (function sourceRandomLogNormal(source) {
  var N = normal_default.source(source);
  function randomLogNormal() {
    var randomNormal = N.apply(this, arguments);
    return function() {
      return Math.exp(randomNormal());
    };
  }
  randomLogNormal.source = sourceRandomLogNormal;
  return randomLogNormal;
})(defaultSource_default);

// node_modules/d3-random/src/irwinHall.js
var irwinHall_default = (function sourceRandomIrwinHall(source) {
  function randomIrwinHall(n) {
    if ((n = +n) <= 0) return () => 0;
    return function() {
      for (var sum4 = 0, i = n; i > 1; --i) sum4 += source();
      return sum4 + i * source();
    };
  }
  randomIrwinHall.source = sourceRandomIrwinHall;
  return randomIrwinHall;
})(defaultSource_default);

// node_modules/d3-random/src/bates.js
var bates_default = (function sourceRandomBates(source) {
  var I = irwinHall_default.source(source);
  function randomBates(n) {
    if ((n = +n) === 0) return source;
    var randomIrwinHall = I(n);
    return function() {
      return randomIrwinHall() / n;
    };
  }
  randomBates.source = sourceRandomBates;
  return randomBates;
})(defaultSource_default);

// node_modules/d3-random/src/exponential.js
var exponential_default = (function sourceRandomExponential(source) {
  function randomExponential(lambda) {
    return function() {
      return -Math.log1p(-source()) / lambda;
    };
  }
  randomExponential.source = sourceRandomExponential;
  return randomExponential;
})(defaultSource_default);

// node_modules/d3-random/src/pareto.js
var pareto_default = (function sourceRandomPareto(source) {
  function randomPareto(alpha) {
    if ((alpha = +alpha) < 0) throw new RangeError("invalid alpha");
    alpha = 1 / -alpha;
    return function() {
      return Math.pow(1 - source(), alpha);
    };
  }
  randomPareto.source = sourceRandomPareto;
  return randomPareto;
})(defaultSource_default);

// node_modules/d3-random/src/bernoulli.js
var bernoulli_default = (function sourceRandomBernoulli(source) {
  function randomBernoulli(p) {
    if ((p = +p) < 0 || p > 1) throw new RangeError("invalid p");
    return function() {
      return Math.floor(source() + p);
    };
  }
  randomBernoulli.source = sourceRandomBernoulli;
  return randomBernoulli;
})(defaultSource_default);

// node_modules/d3-random/src/geometric.js
var geometric_default = (function sourceRandomGeometric(source) {
  function randomGeometric(p) {
    if ((p = +p) < 0 || p > 1) throw new RangeError("invalid p");
    if (p === 0) return () => Infinity;
    if (p === 1) return () => 1;
    p = Math.log1p(-p);
    return function() {
      return 1 + Math.floor(Math.log1p(-source()) / p);
    };
  }
  randomGeometric.source = sourceRandomGeometric;
  return randomGeometric;
})(defaultSource_default);

// node_modules/d3-random/src/gamma.js
var gamma_default = (function sourceRandomGamma(source) {
  var randomNormal = normal_default.source(source)();
  function randomGamma(k2, theta) {
    if ((k2 = +k2) < 0) throw new RangeError("invalid k");
    if (k2 === 0) return () => 0;
    theta = theta == null ? 1 : +theta;
    if (k2 === 1) return () => -Math.log1p(-source()) * theta;
    var d = (k2 < 1 ? k2 + 1 : k2) - 1 / 3, c4 = 1 / (3 * Math.sqrt(d)), multiplier = k2 < 1 ? () => Math.pow(source(), 1 / k2) : () => 1;
    return function() {
      do {
        do {
          var x3 = randomNormal(), v2 = 1 + c4 * x3;
        } while (v2 <= 0);
        v2 *= v2 * v2;
        var u4 = 1 - source();
      } while (u4 >= 1 - 0.0331 * x3 * x3 * x3 * x3 && Math.log(u4) >= 0.5 * x3 * x3 + d * (1 - v2 + Math.log(v2)));
      return d * v2 * multiplier() * theta;
    };
  }
  randomGamma.source = sourceRandomGamma;
  return randomGamma;
})(defaultSource_default);

// node_modules/d3-random/src/beta.js
var beta_default = (function sourceRandomBeta(source) {
  var G = gamma_default.source(source);
  function randomBeta(alpha, beta) {
    var X3 = G(alpha), Y3 = G(beta);
    return function() {
      var x3 = X3();
      return x3 === 0 ? 0 : x3 / (x3 + Y3());
    };
  }
  randomBeta.source = sourceRandomBeta;
  return randomBeta;
})(defaultSource_default);

// node_modules/d3-random/src/binomial.js
var binomial_default = (function sourceRandomBinomial(source) {
  var G = geometric_default.source(source), B3 = beta_default.source(source);
  function randomBinomial(n, p) {
    n = +n;
    if ((p = +p) >= 1) return () => n;
    if (p <= 0) return () => 0;
    return function() {
      var acc = 0, nn = n, pp = p;
      while (nn * pp > 16 && nn * (1 - pp) > 16) {
        var i = Math.floor((nn + 1) * pp), y3 = B3(i, nn - i + 1)();
        if (y3 <= pp) {
          acc += i;
          nn -= i;
          pp = (pp - y3) / (1 - y3);
        } else {
          nn = i - 1;
          pp /= y3;
        }
      }
      var sign3 = pp < 0.5, pFinal = sign3 ? pp : 1 - pp, g = G(pFinal);
      for (var s2 = g(), k2 = 0; s2 <= nn; ++k2) s2 += g();
      return acc + (sign3 ? k2 : nn - k2);
    };
  }
  randomBinomial.source = sourceRandomBinomial;
  return randomBinomial;
})(defaultSource_default);

// node_modules/d3-random/src/weibull.js
var weibull_default = (function sourceRandomWeibull(source) {
  function randomWeibull(k2, a2, b) {
    var outerFunc;
    if ((k2 = +k2) === 0) {
      outerFunc = (x3) => -Math.log(x3);
    } else {
      k2 = 1 / k2;
      outerFunc = (x3) => Math.pow(x3, k2);
    }
    a2 = a2 == null ? 0 : +a2;
    b = b == null ? 1 : +b;
    return function() {
      return a2 + b * outerFunc(-Math.log1p(-source()));
    };
  }
  randomWeibull.source = sourceRandomWeibull;
  return randomWeibull;
})(defaultSource_default);

// node_modules/d3-random/src/cauchy.js
var cauchy_default = (function sourceRandomCauchy(source) {
  function randomCauchy(a2, b) {
    a2 = a2 == null ? 0 : +a2;
    b = b == null ? 1 : +b;
    return function() {
      return a2 + b * Math.tan(Math.PI * source());
    };
  }
  randomCauchy.source = sourceRandomCauchy;
  return randomCauchy;
})(defaultSource_default);

// node_modules/d3-random/src/logistic.js
var logistic_default = (function sourceRandomLogistic(source) {
  function randomLogistic(a2, b) {
    a2 = a2 == null ? 0 : +a2;
    b = b == null ? 1 : +b;
    return function() {
      var u4 = source();
      return a2 + b * Math.log(u4 / (1 - u4));
    };
  }
  randomLogistic.source = sourceRandomLogistic;
  return randomLogistic;
})(defaultSource_default);

// node_modules/d3-random/src/poisson.js
var poisson_default = (function sourceRandomPoisson(source) {
  var G = gamma_default.source(source), B3 = binomial_default.source(source);
  function randomPoisson(lambda) {
    return function() {
      var acc = 0, l = lambda;
      while (l > 16) {
        var n = Math.floor(0.875 * l), t = G(n)();
        if (t > l) return acc + B3(n - 1, l / t)();
        acc += n;
        l -= t;
      }
      for (var s2 = -Math.log1p(-source()), k2 = 0; s2 <= l; ++k2) s2 -= Math.log1p(-source());
      return acc + k2;
    };
  }
  randomPoisson.source = sourceRandomPoisson;
  return randomPoisson;
})(defaultSource_default);

// node_modules/d3-random/src/lcg.js
var mul = 1664525;
var inc = 1013904223;
var eps = 1 / 4294967296;
function lcg(seed = Math.random()) {
  let state = (0 <= seed && seed < 1 ? seed / eps : Math.abs(seed)) | 0;
  return () => (state = mul * state + inc | 0, eps * (state >>> 0));
}

// node_modules/d3-scale/src/init.js
function initRange(domain, range3) {
  switch (arguments.length) {
    case 0:
      break;
    case 1:
      this.range(domain);
      break;
    default:
      this.range(range3).domain(domain);
      break;
  }
  return this;
}
function initInterpolator(domain, interpolator) {
  switch (arguments.length) {
    case 0:
      break;
    case 1: {
      if (typeof domain === "function") this.interpolator(domain);
      else this.range(domain);
      break;
    }
    default: {
      this.domain(domain);
      if (typeof interpolator === "function") this.interpolator(interpolator);
      else this.range(interpolator);
      break;
    }
  }
  return this;
}

// node_modules/d3-scale/src/ordinal.js
var implicit = Symbol("implicit");
function ordinal() {
  var index2 = new InternMap(), domain = [], range3 = [], unknown = implicit;
  function scale3(d) {
    let i = index2.get(d);
    if (i === void 0) {
      if (unknown !== implicit) return unknown;
      index2.set(d, i = domain.push(d) - 1);
    }
    return range3[i % range3.length];
  }
  scale3.domain = function(_) {
    if (!arguments.length) return domain.slice();
    domain = [], index2 = new InternMap();
    for (const value of _) {
      if (index2.has(value)) continue;
      index2.set(value, domain.push(value) - 1);
    }
    return scale3;
  };
  scale3.range = function(_) {
    return arguments.length ? (range3 = Array.from(_), scale3) : range3.slice();
  };
  scale3.unknown = function(_) {
    return arguments.length ? (unknown = _, scale3) : unknown;
  };
  scale3.copy = function() {
    return ordinal(domain, range3).unknown(unknown);
  };
  initRange.apply(scale3, arguments);
  return scale3;
}

// node_modules/d3-scale/src/band.js
function band() {
  var scale3 = ordinal().unknown(void 0), domain = scale3.domain, ordinalRange2 = scale3.range, r0 = 0, r1 = 1, step, bandwidth, round2 = false, paddingInner = 0, paddingOuter = 0, align = 0.5;
  delete scale3.unknown;
  function rescale() {
    var n = domain().length, reverse3 = r1 < r0, start2 = reverse3 ? r1 : r0, stop = reverse3 ? r0 : r1;
    step = (stop - start2) / Math.max(1, n - paddingInner + paddingOuter * 2);
    if (round2) step = Math.floor(step);
    start2 += (stop - start2 - step * (n - paddingInner)) * align;
    bandwidth = step * (1 - paddingInner);
    if (round2) start2 = Math.round(start2), bandwidth = Math.round(bandwidth);
    var values2 = range(n).map(function(i) {
      return start2 + step * i;
    });
    return ordinalRange2(reverse3 ? values2.reverse() : values2);
  }
  scale3.domain = function(_) {
    return arguments.length ? (domain(_), rescale()) : domain();
  };
  scale3.range = function(_) {
    return arguments.length ? ([r0, r1] = _, r0 = +r0, r1 = +r1, rescale()) : [r0, r1];
  };
  scale3.rangeRound = function(_) {
    return [r0, r1] = _, r0 = +r0, r1 = +r1, round2 = true, rescale();
  };
  scale3.bandwidth = function() {
    return bandwidth;
  };
  scale3.step = function() {
    return step;
  };
  scale3.round = function(_) {
    return arguments.length ? (round2 = !!_, rescale()) : round2;
  };
  scale3.padding = function(_) {
    return arguments.length ? (paddingInner = Math.min(1, paddingOuter = +_), rescale()) : paddingInner;
  };
  scale3.paddingInner = function(_) {
    return arguments.length ? (paddingInner = Math.min(1, _), rescale()) : paddingInner;
  };
  scale3.paddingOuter = function(_) {
    return arguments.length ? (paddingOuter = +_, rescale()) : paddingOuter;
  };
  scale3.align = function(_) {
    return arguments.length ? (align = Math.max(0, Math.min(1, _)), rescale()) : align;
  };
  scale3.copy = function() {
    return band(domain(), [r0, r1]).round(round2).paddingInner(paddingInner).paddingOuter(paddingOuter).align(align);
  };
  return initRange.apply(rescale(), arguments);
}
function pointish(scale3) {
  var copy3 = scale3.copy;
  scale3.padding = scale3.paddingOuter;
  delete scale3.paddingInner;
  delete scale3.paddingOuter;
  scale3.copy = function() {
    return pointish(copy3());
  };
  return scale3;
}
function point() {
  return pointish(band.apply(null, arguments).paddingInner(1));
}

// node_modules/d3-scale/src/constant.js
function constants(x3) {
  return function() {
    return x3;
  };
}

// node_modules/d3-scale/src/number.js
function number3(x3) {
  return +x3;
}

// node_modules/d3-scale/src/continuous.js
var unit = [0, 1];
function identity3(x3) {
  return x3;
}
function normalize2(a2, b) {
  return (b -= a2 = +a2) ? function(x3) {
    return (x3 - a2) / b;
  } : constants(isNaN(b) ? NaN : 0.5);
}
function clamper(a2, b) {
  var t;
  if (a2 > b) t = a2, a2 = b, b = t;
  return function(x3) {
    return Math.max(a2, Math.min(b, x3));
  };
}
function bimap(domain, range3, interpolate) {
  var d0 = domain[0], d1 = domain[1], r0 = range3[0], r1 = range3[1];
  if (d1 < d0) d0 = normalize2(d1, d0), r0 = interpolate(r1, r0);
  else d0 = normalize2(d0, d1), r0 = interpolate(r0, r1);
  return function(x3) {
    return r0(d0(x3));
  };
}
function polymap(domain, range3, interpolate) {
  var j = Math.min(domain.length, range3.length) - 1, d = new Array(j), r = new Array(j), i = -1;
  if (domain[j] < domain[0]) {
    domain = domain.slice().reverse();
    range3 = range3.slice().reverse();
  }
  while (++i < j) {
    d[i] = normalize2(domain[i], domain[i + 1]);
    r[i] = interpolate(range3[i], range3[i + 1]);
  }
  return function(x3) {
    var i2 = bisect_default(domain, x3, 1, j) - 1;
    return r[i2](d[i2](x3));
  };
}
function copy(source, target) {
  return target.domain(source.domain()).range(source.range()).interpolate(source.interpolate()).clamp(source.clamp()).unknown(source.unknown());
}
function transformer2() {
  var domain = unit, range3 = unit, interpolate = value_default, transform2, untransform, unknown, clamp = identity3, piecewise2, output, input;
  function rescale() {
    var n = Math.min(domain.length, range3.length);
    if (clamp !== identity3) clamp = clamper(domain[0], domain[n - 1]);
    piecewise2 = n > 2 ? polymap : bimap;
    output = input = null;
    return scale3;
  }
  function scale3(x3) {
    return x3 == null || isNaN(x3 = +x3) ? unknown : (output || (output = piecewise2(domain.map(transform2), range3, interpolate)))(transform2(clamp(x3)));
  }
  scale3.invert = function(y3) {
    return clamp(untransform((input || (input = piecewise2(range3, domain.map(transform2), number_default)))(y3)));
  };
  scale3.domain = function(_) {
    return arguments.length ? (domain = Array.from(_, number3), rescale()) : domain.slice();
  };
  scale3.range = function(_) {
    return arguments.length ? (range3 = Array.from(_), rescale()) : range3.slice();
  };
  scale3.rangeRound = function(_) {
    return range3 = Array.from(_), interpolate = round_default, rescale();
  };
  scale3.clamp = function(_) {
    return arguments.length ? (clamp = _ ? true : identity3, rescale()) : clamp !== identity3;
  };
  scale3.interpolate = function(_) {
    return arguments.length ? (interpolate = _, rescale()) : interpolate;
  };
  scale3.unknown = function(_) {
    return arguments.length ? (unknown = _, scale3) : unknown;
  };
  return function(t, u4) {
    transform2 = t, untransform = u4;
    return rescale();
  };
}
function continuous() {
  return transformer2()(identity3, identity3);
}

// node_modules/d3-scale/src/tickFormat.js
function tickFormat(start2, stop, count3, specifier) {
  var step = tickStep(start2, stop, count3), precision;
  specifier = formatSpecifier(specifier == null ? ",f" : specifier);
  switch (specifier.type) {
    case "s": {
      var value = Math.max(Math.abs(start2), Math.abs(stop));
      if (specifier.precision == null && !isNaN(precision = precisionPrefix_default(step, value))) specifier.precision = precision;
      return formatPrefix(specifier, value);
    }
    case "":
    case "e":
    case "g":
    case "p":
    case "r": {
      if (specifier.precision == null && !isNaN(precision = precisionRound_default(step, Math.max(Math.abs(start2), Math.abs(stop))))) specifier.precision = precision - (specifier.type === "e");
      break;
    }
    case "f":
    case "%": {
      if (specifier.precision == null && !isNaN(precision = precisionFixed_default(step))) specifier.precision = precision - (specifier.type === "%") * 2;
      break;
    }
  }
  return format(specifier);
}

// node_modules/d3-scale/src/linear.js
function linearish(scale3) {
  var domain = scale3.domain;
  scale3.ticks = function(count3) {
    var d = domain();
    return ticks(d[0], d[d.length - 1], count3 == null ? 10 : count3);
  };
  scale3.tickFormat = function(count3, specifier) {
    var d = domain();
    return tickFormat(d[0], d[d.length - 1], count3 == null ? 10 : count3, specifier);
  };
  scale3.nice = function(count3) {
    if (count3 == null) count3 = 10;
    var d = domain();
    var i0 = 0;
    var i1 = d.length - 1;
    var start2 = d[i0];
    var stop = d[i1];
    var prestep;
    var step;
    var maxIter = 10;
    if (stop < start2) {
      step = start2, start2 = stop, stop = step;
      step = i0, i0 = i1, i1 = step;
    }
    while (maxIter-- > 0) {
      step = tickIncrement(start2, stop, count3);
      if (step === prestep) {
        d[i0] = start2;
        d[i1] = stop;
        return domain(d);
      } else if (step > 0) {
        start2 = Math.floor(start2 / step) * step;
        stop = Math.ceil(stop / step) * step;
      } else if (step < 0) {
        start2 = Math.ceil(start2 * step) / step;
        stop = Math.floor(stop * step) / step;
      } else {
        break;
      }
      prestep = step;
    }
    return scale3;
  };
  return scale3;
}
function linear3() {
  var scale3 = continuous();
  scale3.copy = function() {
    return copy(scale3, linear3());
  };
  initRange.apply(scale3, arguments);
  return linearish(scale3);
}

// node_modules/d3-scale/src/identity.js
function identity4(domain) {
  var unknown;
  function scale3(x3) {
    return x3 == null || isNaN(x3 = +x3) ? unknown : x3;
  }
  scale3.invert = scale3;
  scale3.domain = scale3.range = function(_) {
    return arguments.length ? (domain = Array.from(_, number3), scale3) : domain.slice();
  };
  scale3.unknown = function(_) {
    return arguments.length ? (unknown = _, scale3) : unknown;
  };
  scale3.copy = function() {
    return identity4(domain).unknown(unknown);
  };
  domain = arguments.length ? Array.from(domain, number3) : [0, 1];
  return linearish(scale3);
}

// node_modules/d3-scale/src/nice.js
function nice2(domain, interval2) {
  domain = domain.slice();
  var i0 = 0, i1 = domain.length - 1, x06 = domain[i0], x12 = domain[i1], t;
  if (x12 < x06) {
    t = i0, i0 = i1, i1 = t;
    t = x06, x06 = x12, x12 = t;
  }
  domain[i0] = interval2.floor(x06);
  domain[i1] = interval2.ceil(x12);
  return domain;
}

// node_modules/d3-scale/src/log.js
function transformLog(x3) {
  return Math.log(x3);
}
function transformExp(x3) {
  return Math.exp(x3);
}
function transformLogn(x3) {
  return -Math.log(-x3);
}
function transformExpn(x3) {
  return -Math.exp(-x3);
}
function pow10(x3) {
  return isFinite(x3) ? +("1e" + x3) : x3 < 0 ? 0 : x3;
}
function powp(base) {
  return base === 10 ? pow10 : base === Math.E ? Math.exp : (x3) => Math.pow(base, x3);
}
function logp(base) {
  return base === Math.E ? Math.log : base === 10 && Math.log10 || base === 2 && Math.log2 || (base = Math.log(base), (x3) => Math.log(x3) / base);
}
function reflect(f) {
  return (x3, k2) => -f(-x3, k2);
}
function loggish(transform2) {
  const scale3 = transform2(transformLog, transformExp);
  const domain = scale3.domain;
  let base = 10;
  let logs;
  let pows;
  function rescale() {
    logs = logp(base), pows = powp(base);
    if (domain()[0] < 0) {
      logs = reflect(logs), pows = reflect(pows);
      transform2(transformLogn, transformExpn);
    } else {
      transform2(transformLog, transformExp);
    }
    return scale3;
  }
  scale3.base = function(_) {
    return arguments.length ? (base = +_, rescale()) : base;
  };
  scale3.domain = function(_) {
    return arguments.length ? (domain(_), rescale()) : domain();
  };
  scale3.ticks = (count3) => {
    const d = domain();
    let u4 = d[0];
    let v2 = d[d.length - 1];
    const r = v2 < u4;
    if (r) [u4, v2] = [v2, u4];
    let i = logs(u4);
    let j = logs(v2);
    let k2;
    let t;
    const n = count3 == null ? 10 : +count3;
    let z = [];
    if (!(base % 1) && j - i < n) {
      i = Math.floor(i), j = Math.ceil(j);
      if (u4 > 0) for (; i <= j; ++i) {
        for (k2 = 1; k2 < base; ++k2) {
          t = i < 0 ? k2 / pows(-i) : k2 * pows(i);
          if (t < u4) continue;
          if (t > v2) break;
          z.push(t);
        }
      }
      else for (; i <= j; ++i) {
        for (k2 = base - 1; k2 >= 1; --k2) {
          t = i > 0 ? k2 / pows(-i) : k2 * pows(i);
          if (t < u4) continue;
          if (t > v2) break;
          z.push(t);
        }
      }
      if (z.length * 2 < n) z = ticks(u4, v2, n);
    } else {
      z = ticks(i, j, Math.min(j - i, n)).map(pows);
    }
    return r ? z.reverse() : z;
  };
  scale3.tickFormat = (count3, specifier) => {
    if (count3 == null) count3 = 10;
    if (specifier == null) specifier = base === 10 ? "s" : ",";
    if (typeof specifier !== "function") {
      if (!(base % 1) && (specifier = formatSpecifier(specifier)).precision == null) specifier.trim = true;
      specifier = format(specifier);
    }
    if (count3 === Infinity) return specifier;
    const k2 = Math.max(1, base * count3 / scale3.ticks().length);
    return (d) => {
      let i = d / pows(Math.round(logs(d)));
      if (i * base < base - 0.5) i *= base;
      return i <= k2 ? specifier(d) : "";
    };
  };
  scale3.nice = () => {
    return domain(nice2(domain(), {
      floor: (x3) => pows(Math.floor(logs(x3))),
      ceil: (x3) => pows(Math.ceil(logs(x3)))
    }));
  };
  return scale3;
}
function log2() {
  const scale3 = loggish(transformer2()).domain([1, 10]);
  scale3.copy = () => copy(scale3, log2()).base(scale3.base());
  initRange.apply(scale3, arguments);
  return scale3;
}

// node_modules/d3-scale/src/symlog.js
function transformSymlog(c4) {
  return function(x3) {
    return Math.sign(x3) * Math.log1p(Math.abs(x3 / c4));
  };
}
function transformSymexp(c4) {
  return function(x3) {
    return Math.sign(x3) * Math.expm1(Math.abs(x3)) * c4;
  };
}
function symlogish(transform2) {
  var c4 = 1, scale3 = transform2(transformSymlog(c4), transformSymexp(c4));
  scale3.constant = function(_) {
    return arguments.length ? transform2(transformSymlog(c4 = +_), transformSymexp(c4)) : c4;
  };
  return linearish(scale3);
}
function symlog() {
  var scale3 = symlogish(transformer2());
  scale3.copy = function() {
    return copy(scale3, symlog()).constant(scale3.constant());
  };
  return initRange.apply(scale3, arguments);
}

// node_modules/d3-scale/src/pow.js
function transformPow(exponent2) {
  return function(x3) {
    return x3 < 0 ? -Math.pow(-x3, exponent2) : Math.pow(x3, exponent2);
  };
}
function transformSqrt(x3) {
  return x3 < 0 ? -Math.sqrt(-x3) : Math.sqrt(x3);
}
function transformSquare(x3) {
  return x3 < 0 ? -x3 * x3 : x3 * x3;
}
function powish(transform2) {
  var scale3 = transform2(identity3, identity3), exponent2 = 1;
  function rescale() {
    return exponent2 === 1 ? transform2(identity3, identity3) : exponent2 === 0.5 ? transform2(transformSqrt, transformSquare) : transform2(transformPow(exponent2), transformPow(1 / exponent2));
  }
  scale3.exponent = function(_) {
    return arguments.length ? (exponent2 = +_, rescale()) : exponent2;
  };
  return linearish(scale3);
}
function pow3() {
  var scale3 = powish(transformer2());
  scale3.copy = function() {
    return copy(scale3, pow3()).exponent(scale3.exponent());
  };
  initRange.apply(scale3, arguments);
  return scale3;
}

// node_modules/d3-scale/src/quantile.js
function quantile2() {
  var domain = [], range3 = [], thresholds = [], unknown;
  function rescale() {
    var i = 0, n = Math.max(1, range3.length);
    thresholds = new Array(n - 1);
    while (++i < n) thresholds[i - 1] = quantileSorted(domain, i / n);
    return scale3;
  }
  function scale3(x3) {
    return x3 == null || isNaN(x3 = +x3) ? unknown : range3[bisect_default(thresholds, x3)];
  }
  scale3.invertExtent = function(y3) {
    var i = range3.indexOf(y3);
    return i < 0 ? [NaN, NaN] : [
      i > 0 ? thresholds[i - 1] : domain[0],
      i < thresholds.length ? thresholds[i] : domain[domain.length - 1]
    ];
  };
  scale3.domain = function(_) {
    if (!arguments.length) return domain.slice();
    domain = [];
    for (let d of _) if (d != null && !isNaN(d = +d)) domain.push(d);
    domain.sort(ascending);
    return rescale();
  };
  scale3.range = function(_) {
    return arguments.length ? (range3 = Array.from(_), rescale()) : range3.slice();
  };
  scale3.unknown = function(_) {
    return arguments.length ? (unknown = _, scale3) : unknown;
  };
  scale3.quantiles = function() {
    return thresholds.slice();
  };
  scale3.copy = function() {
    return quantile2().domain(domain).range(range3).unknown(unknown);
  };
  return initRange.apply(scale3, arguments);
}

// node_modules/d3-scale/src/threshold.js
function threshold() {
  var domain = [0.5], range3 = [0, 1], unknown, n = 1;
  function scale3(x3) {
    return x3 != null && x3 <= x3 ? range3[bisect_default(domain, x3, 0, n)] : unknown;
  }
  scale3.domain = function(_) {
    return arguments.length ? (domain = Array.from(_), n = Math.min(domain.length, range3.length - 1), scale3) : domain.slice();
  };
  scale3.range = function(_) {
    return arguments.length ? (range3 = Array.from(_), n = Math.min(domain.length, range3.length - 1), scale3) : range3.slice();
  };
  scale3.invertExtent = function(y3) {
    var i = range3.indexOf(y3);
    return [domain[i - 1], domain[i]];
  };
  scale3.unknown = function(_) {
    return arguments.length ? (unknown = _, scale3) : unknown;
  };
  scale3.copy = function() {
    return threshold().domain(domain).range(range3).unknown(unknown);
  };
  return initRange.apply(scale3, arguments);
}

// node_modules/d3-time/src/interval.js
var t02 = /* @__PURE__ */ new Date();
var t12 = /* @__PURE__ */ new Date();
function timeInterval(floori, offseti, count3, field2) {
  function interval2(date2) {
    return floori(date2 = arguments.length === 0 ? /* @__PURE__ */ new Date() : /* @__PURE__ */ new Date(+date2)), date2;
  }
  interval2.floor = (date2) => {
    return floori(date2 = /* @__PURE__ */ new Date(+date2)), date2;
  };
  interval2.ceil = (date2) => {
    return floori(date2 = new Date(date2 - 1)), offseti(date2, 1), floori(date2), date2;
  };
  interval2.round = (date2) => {
    const d0 = interval2(date2), d1 = interval2.ceil(date2);
    return date2 - d0 < d1 - date2 ? d0 : d1;
  };
  interval2.offset = (date2, step) => {
    return offseti(date2 = /* @__PURE__ */ new Date(+date2), step == null ? 1 : Math.floor(step)), date2;
  };
  interval2.range = (start2, stop, step) => {
    const range3 = [];
    start2 = interval2.ceil(start2);
    step = step == null ? 1 : Math.floor(step);
    if (!(start2 < stop) || !(step > 0)) return range3;
    let previous;
    do
      range3.push(previous = /* @__PURE__ */ new Date(+start2)), offseti(start2, step), floori(start2);
    while (previous < start2 && start2 < stop);
    return range3;
  };
  interval2.filter = (test) => {
    return timeInterval((date2) => {
      if (date2 >= date2) while (floori(date2), !test(date2)) date2.setTime(date2 - 1);
    }, (date2, step) => {
      if (date2 >= date2) {
        if (step < 0) while (++step <= 0) {
          while (offseti(date2, -1), !test(date2)) {
          }
        }
        else while (--step >= 0) {
          while (offseti(date2, 1), !test(date2)) {
          }
        }
      }
    });
  };
  if (count3) {
    interval2.count = (start2, end) => {
      t02.setTime(+start2), t12.setTime(+end);
      floori(t02), floori(t12);
      return Math.floor(count3(t02, t12));
    };
    interval2.every = (step) => {
      step = Math.floor(step);
      return !isFinite(step) || !(step > 0) ? null : !(step > 1) ? interval2 : interval2.filter(field2 ? (d) => field2(d) % step === 0 : (d) => interval2.count(0, d) % step === 0);
    };
  }
  return interval2;
}

// node_modules/d3-time/src/millisecond.js
var millisecond = timeInterval(() => {
}, (date2, step) => {
  date2.setTime(+date2 + step);
}, (start2, end) => {
  return end - start2;
});
millisecond.every = (k2) => {
  k2 = Math.floor(k2);
  if (!isFinite(k2) || !(k2 > 0)) return null;
  if (!(k2 > 1)) return millisecond;
  return timeInterval((date2) => {
    date2.setTime(Math.floor(date2 / k2) * k2);
  }, (date2, step) => {
    date2.setTime(+date2 + step * k2);
  }, (start2, end) => {
    return (end - start2) / k2;
  });
};
var milliseconds = millisecond.range;

// node_modules/d3-time/src/duration.js
var durationSecond = 1e3;
var durationMinute = durationSecond * 60;
var durationHour = durationMinute * 60;
var durationDay = durationHour * 24;
var durationWeek = durationDay * 7;
var durationMonth = durationDay * 30;
var durationYear = durationDay * 365;

// node_modules/d3-time/src/second.js
var second = timeInterval((date2) => {
  date2.setTime(date2 - date2.getMilliseconds());
}, (date2, step) => {
  date2.setTime(+date2 + step * durationSecond);
}, (start2, end) => {
  return (end - start2) / durationSecond;
}, (date2) => {
  return date2.getUTCSeconds();
});
var seconds = second.range;

// node_modules/d3-time/src/minute.js
var timeMinute = timeInterval((date2) => {
  date2.setTime(date2 - date2.getMilliseconds() - date2.getSeconds() * durationSecond);
}, (date2, step) => {
  date2.setTime(+date2 + step * durationMinute);
}, (start2, end) => {
  return (end - start2) / durationMinute;
}, (date2) => {
  return date2.getMinutes();
});
var timeMinutes = timeMinute.range;
var utcMinute = timeInterval((date2) => {
  date2.setUTCSeconds(0, 0);
}, (date2, step) => {
  date2.setTime(+date2 + step * durationMinute);
}, (start2, end) => {
  return (end - start2) / durationMinute;
}, (date2) => {
  return date2.getUTCMinutes();
});
var utcMinutes = utcMinute.range;

// node_modules/d3-time/src/hour.js
var timeHour = timeInterval((date2) => {
  date2.setTime(date2 - date2.getMilliseconds() - date2.getSeconds() * durationSecond - date2.getMinutes() * durationMinute);
}, (date2, step) => {
  date2.setTime(+date2 + step * durationHour);
}, (start2, end) => {
  return (end - start2) / durationHour;
}, (date2) => {
  return date2.getHours();
});
var timeHours = timeHour.range;
var utcHour = timeInterval((date2) => {
  date2.setUTCMinutes(0, 0, 0);
}, (date2, step) => {
  date2.setTime(+date2 + step * durationHour);
}, (start2, end) => {
  return (end - start2) / durationHour;
}, (date2) => {
  return date2.getUTCHours();
});
var utcHours = utcHour.range;

// node_modules/d3-time/src/day.js
var timeDay = timeInterval(
  (date2) => date2.setHours(0, 0, 0, 0),
  (date2, step) => date2.setDate(date2.getDate() + step),
  (start2, end) => (end - start2 - (end.getTimezoneOffset() - start2.getTimezoneOffset()) * durationMinute) / durationDay,
  (date2) => date2.getDate() - 1
);
var timeDays = timeDay.range;
var utcDay = timeInterval((date2) => {
  date2.setUTCHours(0, 0, 0, 0);
}, (date2, step) => {
  date2.setUTCDate(date2.getUTCDate() + step);
}, (start2, end) => {
  return (end - start2) / durationDay;
}, (date2) => {
  return date2.getUTCDate() - 1;
});
var utcDays = utcDay.range;
var unixDay = timeInterval((date2) => {
  date2.setUTCHours(0, 0, 0, 0);
}, (date2, step) => {
  date2.setUTCDate(date2.getUTCDate() + step);
}, (start2, end) => {
  return (end - start2) / durationDay;
}, (date2) => {
  return Math.floor(date2 / durationDay);
});
var unixDays = unixDay.range;

// node_modules/d3-time/src/week.js
function timeWeekday(i) {
  return timeInterval((date2) => {
    date2.setDate(date2.getDate() - (date2.getDay() + 7 - i) % 7);
    date2.setHours(0, 0, 0, 0);
  }, (date2, step) => {
    date2.setDate(date2.getDate() + step * 7);
  }, (start2, end) => {
    return (end - start2 - (end.getTimezoneOffset() - start2.getTimezoneOffset()) * durationMinute) / durationWeek;
  });
}
var timeSunday = timeWeekday(0);
var timeMonday = timeWeekday(1);
var timeTuesday = timeWeekday(2);
var timeWednesday = timeWeekday(3);
var timeThursday = timeWeekday(4);
var timeFriday = timeWeekday(5);
var timeSaturday = timeWeekday(6);
var timeSundays = timeSunday.range;
var timeMondays = timeMonday.range;
var timeTuesdays = timeTuesday.range;
var timeWednesdays = timeWednesday.range;
var timeThursdays = timeThursday.range;
var timeFridays = timeFriday.range;
var timeSaturdays = timeSaturday.range;
function utcWeekday(i) {
  return timeInterval((date2) => {
    date2.setUTCDate(date2.getUTCDate() - (date2.getUTCDay() + 7 - i) % 7);
    date2.setUTCHours(0, 0, 0, 0);
  }, (date2, step) => {
    date2.setUTCDate(date2.getUTCDate() + step * 7);
  }, (start2, end) => {
    return (end - start2) / durationWeek;
  });
}
var utcSunday = utcWeekday(0);
var utcMonday = utcWeekday(1);
var utcTuesday = utcWeekday(2);
var utcWednesday = utcWeekday(3);
var utcThursday = utcWeekday(4);
var utcFriday = utcWeekday(5);
var utcSaturday = utcWeekday(6);
var utcSundays = utcSunday.range;
var utcMondays = utcMonday.range;
var utcTuesdays = utcTuesday.range;
var utcWednesdays = utcWednesday.range;
var utcThursdays = utcThursday.range;
var utcFridays = utcFriday.range;
var utcSaturdays = utcSaturday.range;

// node_modules/d3-time/src/month.js
var timeMonth = timeInterval((date2) => {
  date2.setDate(1);
  date2.setHours(0, 0, 0, 0);
}, (date2, step) => {
  date2.setMonth(date2.getMonth() + step);
}, (start2, end) => {
  return end.getMonth() - start2.getMonth() + (end.getFullYear() - start2.getFullYear()) * 12;
}, (date2) => {
  return date2.getMonth();
});
var timeMonths = timeMonth.range;
var utcMonth = timeInterval((date2) => {
  date2.setUTCDate(1);
  date2.setUTCHours(0, 0, 0, 0);
}, (date2, step) => {
  date2.setUTCMonth(date2.getUTCMonth() + step);
}, (start2, end) => {
  return end.getUTCMonth() - start2.getUTCMonth() + (end.getUTCFullYear() - start2.getUTCFullYear()) * 12;
}, (date2) => {
  return date2.getUTCMonth();
});
var utcMonths = utcMonth.range;

// node_modules/d3-time/src/year.js
var timeYear = timeInterval((date2) => {
  date2.setMonth(0, 1);
  date2.setHours(0, 0, 0, 0);
}, (date2, step) => {
  date2.setFullYear(date2.getFullYear() + step);
}, (start2, end) => {
  return end.getFullYear() - start2.getFullYear();
}, (date2) => {
  return date2.getFullYear();
});
timeYear.every = (k2) => {
  return !isFinite(k2 = Math.floor(k2)) || !(k2 > 0) ? null : timeInterval((date2) => {
    date2.setFullYear(Math.floor(date2.getFullYear() / k2) * k2);
    date2.setMonth(0, 1);
    date2.setHours(0, 0, 0, 0);
  }, (date2, step) => {
    date2.setFullYear(date2.getFullYear() + step * k2);
  });
};
var timeYears = timeYear.range;
var utcYear = timeInterval((date2) => {
  date2.setUTCMonth(0, 1);
  date2.setUTCHours(0, 0, 0, 0);
}, (date2, step) => {
  date2.setUTCFullYear(date2.getUTCFullYear() + step);
}, (start2, end) => {
  return end.getUTCFullYear() - start2.getUTCFullYear();
}, (date2) => {
  return date2.getUTCFullYear();
});
utcYear.every = (k2) => {
  return !isFinite(k2 = Math.floor(k2)) || !(k2 > 0) ? null : timeInterval((date2) => {
    date2.setUTCFullYear(Math.floor(date2.getUTCFullYear() / k2) * k2);
    date2.setUTCMonth(0, 1);
    date2.setUTCHours(0, 0, 0, 0);
  }, (date2, step) => {
    date2.setUTCFullYear(date2.getUTCFullYear() + step * k2);
  });
};
var utcYears = utcYear.range;

// node_modules/d3-time/src/ticks.js
function ticker(year, month, week, day, hour, minute) {
  const tickIntervals2 = [
    [second, 1, durationSecond],
    [second, 5, 5 * durationSecond],
    [second, 15, 15 * durationSecond],
    [second, 30, 30 * durationSecond],
    [minute, 1, durationMinute],
    [minute, 5, 5 * durationMinute],
    [minute, 15, 15 * durationMinute],
    [minute, 30, 30 * durationMinute],
    [hour, 1, durationHour],
    [hour, 3, 3 * durationHour],
    [hour, 6, 6 * durationHour],
    [hour, 12, 12 * durationHour],
    [day, 1, durationDay],
    [day, 2, 2 * durationDay],
    [week, 1, durationWeek],
    [month, 1, durationMonth],
    [month, 3, 3 * durationMonth],
    [year, 1, durationYear]
  ];
  function ticks2(start2, stop, count3) {
    const reverse3 = stop < start2;
    if (reverse3) [start2, stop] = [stop, start2];
    const interval2 = count3 && typeof count3.range === "function" ? count3 : tickInterval(start2, stop, count3);
    const ticks3 = interval2 ? interval2.range(start2, +stop + 1) : [];
    return reverse3 ? ticks3.reverse() : ticks3;
  }
  function tickInterval(start2, stop, count3) {
    const target = Math.abs(stop - start2) / count3;
    const i = bisector(([, , step2]) => step2).right(tickIntervals2, target);
    if (i === tickIntervals2.length) return year.every(tickStep(start2 / durationYear, stop / durationYear, count3));
    if (i === 0) return millisecond.every(Math.max(tickStep(start2, stop, count3), 1));
    const [t, step] = tickIntervals2[target / tickIntervals2[i - 1][2] < tickIntervals2[i][2] / target ? i - 1 : i];
    return t.every(step);
  }
  return [ticks2, tickInterval];
}
var [utcTicks, utcTickInterval] = ticker(utcYear, utcMonth, utcSunday, unixDay, utcHour, utcMinute);
var [timeTicks, timeTickInterval] = ticker(timeYear, timeMonth, timeSunday, timeDay, timeHour, timeMinute);

// node_modules/d3-time-format/src/locale.js
function localDate(d) {
  if (0 <= d.y && d.y < 100) {
    var date2 = new Date(-1, d.m, d.d, d.H, d.M, d.S, d.L);
    date2.setFullYear(d.y);
    return date2;
  }
  return new Date(d.y, d.m, d.d, d.H, d.M, d.S, d.L);
}
function utcDate(d) {
  if (0 <= d.y && d.y < 100) {
    var date2 = new Date(Date.UTC(-1, d.m, d.d, d.H, d.M, d.S, d.L));
    date2.setUTCFullYear(d.y);
    return date2;
  }
  return new Date(Date.UTC(d.y, d.m, d.d, d.H, d.M, d.S, d.L));
}
function newDate(y3, m, d) {
  return { y: y3, m, d, H: 0, M: 0, S: 0, L: 0 };
}
function formatLocale(locale3) {
  var locale_dateTime = locale3.dateTime, locale_date = locale3.date, locale_time = locale3.time, locale_periods = locale3.periods, locale_weekdays = locale3.days, locale_shortWeekdays = locale3.shortDays, locale_months = locale3.months, locale_shortMonths = locale3.shortMonths;
  var periodRe = formatRe(locale_periods), periodLookup = formatLookup(locale_periods), weekdayRe = formatRe(locale_weekdays), weekdayLookup = formatLookup(locale_weekdays), shortWeekdayRe = formatRe(locale_shortWeekdays), shortWeekdayLookup = formatLookup(locale_shortWeekdays), monthRe = formatRe(locale_months), monthLookup = formatLookup(locale_months), shortMonthRe = formatRe(locale_shortMonths), shortMonthLookup = formatLookup(locale_shortMonths);
  var formats = {
    "a": formatShortWeekday,
    "A": formatWeekday2,
    "b": formatShortMonth,
    "B": formatMonth2,
    "c": null,
    "d": formatDayOfMonth,
    "e": formatDayOfMonth,
    "f": formatMicroseconds,
    "g": formatYearISO,
    "G": formatFullYearISO,
    "H": formatHour24,
    "I": formatHour12,
    "j": formatDayOfYear,
    "L": formatMilliseconds,
    "m": formatMonthNumber,
    "M": formatMinutes,
    "p": formatPeriod,
    "q": formatQuarter,
    "Q": formatUnixTimestamp,
    "s": formatUnixTimestampSeconds,
    "S": formatSeconds,
    "u": formatWeekdayNumberMonday,
    "U": formatWeekNumberSunday,
    "V": formatWeekNumberISO,
    "w": formatWeekdayNumberSunday,
    "W": formatWeekNumberMonday,
    "x": null,
    "X": null,
    "y": formatYear2,
    "Y": formatFullYear,
    "Z": formatZone,
    "%": formatLiteralPercent
  };
  var utcFormats = {
    "a": formatUTCShortWeekday,
    "A": formatUTCWeekday,
    "b": formatUTCShortMonth,
    "B": formatUTCMonth,
    "c": null,
    "d": formatUTCDayOfMonth,
    "e": formatUTCDayOfMonth,
    "f": formatUTCMicroseconds,
    "g": formatUTCYearISO,
    "G": formatUTCFullYearISO,
    "H": formatUTCHour24,
    "I": formatUTCHour12,
    "j": formatUTCDayOfYear,
    "L": formatUTCMilliseconds,
    "m": formatUTCMonthNumber,
    "M": formatUTCMinutes,
    "p": formatUTCPeriod,
    "q": formatUTCQuarter,
    "Q": formatUnixTimestamp,
    "s": formatUnixTimestampSeconds,
    "S": formatUTCSeconds,
    "u": formatUTCWeekdayNumberMonday,
    "U": formatUTCWeekNumberSunday,
    "V": formatUTCWeekNumberISO,
    "w": formatUTCWeekdayNumberSunday,
    "W": formatUTCWeekNumberMonday,
    "x": null,
    "X": null,
    "y": formatUTCYear,
    "Y": formatUTCFullYear,
    "Z": formatUTCZone,
    "%": formatLiteralPercent
  };
  var parses = {
    "a": parseShortWeekday,
    "A": parseWeekday,
    "b": parseShortMonth,
    "B": parseMonth,
    "c": parseLocaleDateTime,
    "d": parseDayOfMonth,
    "e": parseDayOfMonth,
    "f": parseMicroseconds,
    "g": parseYear,
    "G": parseFullYear,
    "H": parseHour24,
    "I": parseHour24,
    "j": parseDayOfYear,
    "L": parseMilliseconds,
    "m": parseMonthNumber,
    "M": parseMinutes,
    "p": parsePeriod,
    "q": parseQuarter,
    "Q": parseUnixTimestamp,
    "s": parseUnixTimestampSeconds,
    "S": parseSeconds,
    "u": parseWeekdayNumberMonday,
    "U": parseWeekNumberSunday,
    "V": parseWeekNumberISO,
    "w": parseWeekdayNumberSunday,
    "W": parseWeekNumberMonday,
    "x": parseLocaleDate,
    "X": parseLocaleTime,
    "y": parseYear,
    "Y": parseFullYear,
    "Z": parseZone,
    "%": parseLiteralPercent
  };
  formats.x = newFormat(locale_date, formats);
  formats.X = newFormat(locale_time, formats);
  formats.c = newFormat(locale_dateTime, formats);
  utcFormats.x = newFormat(locale_date, utcFormats);
  utcFormats.X = newFormat(locale_time, utcFormats);
  utcFormats.c = newFormat(locale_dateTime, utcFormats);
  function newFormat(specifier, formats2) {
    return function(date2) {
      var string2 = [], i = -1, j = 0, n = specifier.length, c4, pad4, format3;
      if (!(date2 instanceof Date)) date2 = /* @__PURE__ */ new Date(+date2);
      while (++i < n) {
        if (specifier.charCodeAt(i) === 37) {
          string2.push(specifier.slice(j, i));
          if ((pad4 = pads[c4 = specifier.charAt(++i)]) != null) c4 = specifier.charAt(++i);
          else pad4 = c4 === "e" ? " " : "0";
          if (format3 = formats2[c4]) c4 = format3(date2, pad4);
          string2.push(c4);
          j = i + 1;
        }
      }
      string2.push(specifier.slice(j, i));
      return string2.join("");
    };
  }
  function newParse(specifier, Z) {
    return function(string2) {
      var d = newDate(1900, void 0, 1), i = parseSpecifier(d, specifier, string2 += "", 0), week, day;
      if (i != string2.length) return null;
      if ("Q" in d) return new Date(d.Q);
      if ("s" in d) return new Date(d.s * 1e3 + ("L" in d ? d.L : 0));
      if (Z && !("Z" in d)) d.Z = 0;
      if ("p" in d) d.H = d.H % 12 + d.p * 12;
      if (d.m === void 0) d.m = "q" in d ? d.q : 0;
      if ("V" in d) {
        if (d.V < 1 || d.V > 53) return null;
        if (!("w" in d)) d.w = 1;
        if ("Z" in d) {
          week = utcDate(newDate(d.y, 0, 1)), day = week.getUTCDay();
          week = day > 4 || day === 0 ? utcMonday.ceil(week) : utcMonday(week);
          week = utcDay.offset(week, (d.V - 1) * 7);
          d.y = week.getUTCFullYear();
          d.m = week.getUTCMonth();
          d.d = week.getUTCDate() + (d.w + 6) % 7;
        } else {
          week = localDate(newDate(d.y, 0, 1)), day = week.getDay();
          week = day > 4 || day === 0 ? timeMonday.ceil(week) : timeMonday(week);
          week = timeDay.offset(week, (d.V - 1) * 7);
          d.y = week.getFullYear();
          d.m = week.getMonth();
          d.d = week.getDate() + (d.w + 6) % 7;
        }
      } else if ("W" in d || "U" in d) {
        if (!("w" in d)) d.w = "u" in d ? d.u % 7 : "W" in d ? 1 : 0;
        day = "Z" in d ? utcDate(newDate(d.y, 0, 1)).getUTCDay() : localDate(newDate(d.y, 0, 1)).getDay();
        d.m = 0;
        d.d = "W" in d ? (d.w + 6) % 7 + d.W * 7 - (day + 5) % 7 : d.w + d.U * 7 - (day + 6) % 7;
      }
      if ("Z" in d) {
        d.H += d.Z / 100 | 0;
        d.M += d.Z % 100;
        return utcDate(d);
      }
      return localDate(d);
    };
  }
  function parseSpecifier(d, specifier, string2, j) {
    var i = 0, n = specifier.length, m = string2.length, c4, parse2;
    while (i < n) {
      if (j >= m) return -1;
      c4 = specifier.charCodeAt(i++);
      if (c4 === 37) {
        c4 = specifier.charAt(i++);
        parse2 = parses[c4 in pads ? specifier.charAt(i++) : c4];
        if (!parse2 || (j = parse2(d, string2, j)) < 0) return -1;
      } else if (c4 != string2.charCodeAt(j++)) {
        return -1;
      }
    }
    return j;
  }
  function parsePeriod(d, string2, i) {
    var n = periodRe.exec(string2.slice(i));
    return n ? (d.p = periodLookup.get(n[0].toLowerCase()), i + n[0].length) : -1;
  }
  function parseShortWeekday(d, string2, i) {
    var n = shortWeekdayRe.exec(string2.slice(i));
    return n ? (d.w = shortWeekdayLookup.get(n[0].toLowerCase()), i + n[0].length) : -1;
  }
  function parseWeekday(d, string2, i) {
    var n = weekdayRe.exec(string2.slice(i));
    return n ? (d.w = weekdayLookup.get(n[0].toLowerCase()), i + n[0].length) : -1;
  }
  function parseShortMonth(d, string2, i) {
    var n = shortMonthRe.exec(string2.slice(i));
    return n ? (d.m = shortMonthLookup.get(n[0].toLowerCase()), i + n[0].length) : -1;
  }
  function parseMonth(d, string2, i) {
    var n = monthRe.exec(string2.slice(i));
    return n ? (d.m = monthLookup.get(n[0].toLowerCase()), i + n[0].length) : -1;
  }
  function parseLocaleDateTime(d, string2, i) {
    return parseSpecifier(d, locale_dateTime, string2, i);
  }
  function parseLocaleDate(d, string2, i) {
    return parseSpecifier(d, locale_date, string2, i);
  }
  function parseLocaleTime(d, string2, i) {
    return parseSpecifier(d, locale_time, string2, i);
  }
  function formatShortWeekday(d) {
    return locale_shortWeekdays[d.getDay()];
  }
  function formatWeekday2(d) {
    return locale_weekdays[d.getDay()];
  }
  function formatShortMonth(d) {
    return locale_shortMonths[d.getMonth()];
  }
  function formatMonth2(d) {
    return locale_months[d.getMonth()];
  }
  function formatPeriod(d) {
    return locale_periods[+(d.getHours() >= 12)];
  }
  function formatQuarter(d) {
    return 1 + ~~(d.getMonth() / 3);
  }
  function formatUTCShortWeekday(d) {
    return locale_shortWeekdays[d.getUTCDay()];
  }
  function formatUTCWeekday(d) {
    return locale_weekdays[d.getUTCDay()];
  }
  function formatUTCShortMonth(d) {
    return locale_shortMonths[d.getUTCMonth()];
  }
  function formatUTCMonth(d) {
    return locale_months[d.getUTCMonth()];
  }
  function formatUTCPeriod(d) {
    return locale_periods[+(d.getUTCHours() >= 12)];
  }
  function formatUTCQuarter(d) {
    return 1 + ~~(d.getUTCMonth() / 3);
  }
  return {
    format: function(specifier) {
      var f = newFormat(specifier += "", formats);
      f.toString = function() {
        return specifier;
      };
      return f;
    },
    parse: function(specifier) {
      var p = newParse(specifier += "", false);
      p.toString = function() {
        return specifier;
      };
      return p;
    },
    utcFormat: function(specifier) {
      var f = newFormat(specifier += "", utcFormats);
      f.toString = function() {
        return specifier;
      };
      return f;
    },
    utcParse: function(specifier) {
      var p = newParse(specifier += "", true);
      p.toString = function() {
        return specifier;
      };
      return p;
    }
  };
}
var pads = { "-": "", "_": " ", "0": "0" };
var numberRe = /^\s*\d+/;
var percentRe = /^%/;
var requoteRe = /[\\^$*+?|[\]().{}]/g;
function pad2(value, fill, width) {
  var sign3 = value < 0 ? "-" : "", string2 = (sign3 ? -value : value) + "", length3 = string2.length;
  return sign3 + (length3 < width ? new Array(width - length3 + 1).join(fill) + string2 : string2);
}
function requote(s2) {
  return s2.replace(requoteRe, "\\$&");
}
function formatRe(names) {
  return new RegExp("^(?:" + names.map(requote).join("|") + ")", "i");
}
function formatLookup(names) {
  return new Map(names.map((name, i) => [name.toLowerCase(), i]));
}
function parseWeekdayNumberSunday(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 1));
  return n ? (d.w = +n[0], i + n[0].length) : -1;
}
function parseWeekdayNumberMonday(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 1));
  return n ? (d.u = +n[0], i + n[0].length) : -1;
}
function parseWeekNumberSunday(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.U = +n[0], i + n[0].length) : -1;
}
function parseWeekNumberISO(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.V = +n[0], i + n[0].length) : -1;
}
function parseWeekNumberMonday(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.W = +n[0], i + n[0].length) : -1;
}
function parseFullYear(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 4));
  return n ? (d.y = +n[0], i + n[0].length) : -1;
}
function parseYear(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.y = +n[0] + (+n[0] > 68 ? 1900 : 2e3), i + n[0].length) : -1;
}
function parseZone(d, string2, i) {
  var n = /^(Z)|([+-]\d\d)(?::?(\d\d))?/.exec(string2.slice(i, i + 6));
  return n ? (d.Z = n[1] ? 0 : -(n[2] + (n[3] || "00")), i + n[0].length) : -1;
}
function parseQuarter(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 1));
  return n ? (d.q = n[0] * 3 - 3, i + n[0].length) : -1;
}
function parseMonthNumber(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.m = n[0] - 1, i + n[0].length) : -1;
}
function parseDayOfMonth(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.d = +n[0], i + n[0].length) : -1;
}
function parseDayOfYear(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 3));
  return n ? (d.m = 0, d.d = +n[0], i + n[0].length) : -1;
}
function parseHour24(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.H = +n[0], i + n[0].length) : -1;
}
function parseMinutes(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.M = +n[0], i + n[0].length) : -1;
}
function parseSeconds(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 2));
  return n ? (d.S = +n[0], i + n[0].length) : -1;
}
function parseMilliseconds(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 3));
  return n ? (d.L = +n[0], i + n[0].length) : -1;
}
function parseMicroseconds(d, string2, i) {
  var n = numberRe.exec(string2.slice(i, i + 6));
  return n ? (d.L = Math.floor(n[0] / 1e3), i + n[0].length) : -1;
}
function parseLiteralPercent(d, string2, i) {
  var n = percentRe.exec(string2.slice(i, i + 1));
  return n ? i + n[0].length : -1;
}
function parseUnixTimestamp(d, string2, i) {
  var n = numberRe.exec(string2.slice(i));
  return n ? (d.Q = +n[0], i + n[0].length) : -1;
}
function parseUnixTimestampSeconds(d, string2, i) {
  var n = numberRe.exec(string2.slice(i));
  return n ? (d.s = +n[0], i + n[0].length) : -1;
}
function formatDayOfMonth(d, p) {
  return pad2(d.getDate(), p, 2);
}
function formatHour24(d, p) {
  return pad2(d.getHours(), p, 2);
}
function formatHour12(d, p) {
  return pad2(d.getHours() % 12 || 12, p, 2);
}
function formatDayOfYear(d, p) {
  return pad2(1 + timeDay.count(timeYear(d), d), p, 3);
}
function formatMilliseconds(d, p) {
  return pad2(d.getMilliseconds(), p, 3);
}
function formatMicroseconds(d, p) {
  return formatMilliseconds(d, p) + "000";
}
function formatMonthNumber(d, p) {
  return pad2(d.getMonth() + 1, p, 2);
}
function formatMinutes(d, p) {
  return pad2(d.getMinutes(), p, 2);
}
function formatSeconds(d, p) {
  return pad2(d.getSeconds(), p, 2);
}
function formatWeekdayNumberMonday(d) {
  var day = d.getDay();
  return day === 0 ? 7 : day;
}
function formatWeekNumberSunday(d, p) {
  return pad2(timeSunday.count(timeYear(d) - 1, d), p, 2);
}
function dISO(d) {
  var day = d.getDay();
  return day >= 4 || day === 0 ? timeThursday(d) : timeThursday.ceil(d);
}
function formatWeekNumberISO(d, p) {
  d = dISO(d);
  return pad2(timeThursday.count(timeYear(d), d) + (timeYear(d).getDay() === 4), p, 2);
}
function formatWeekdayNumberSunday(d) {
  return d.getDay();
}
function formatWeekNumberMonday(d, p) {
  return pad2(timeMonday.count(timeYear(d) - 1, d), p, 2);
}
function formatYear2(d, p) {
  return pad2(d.getFullYear() % 100, p, 2);
}
function formatYearISO(d, p) {
  d = dISO(d);
  return pad2(d.getFullYear() % 100, p, 2);
}
function formatFullYear(d, p) {
  return pad2(d.getFullYear() % 1e4, p, 4);
}
function formatFullYearISO(d, p) {
  var day = d.getDay();
  d = day >= 4 || day === 0 ? timeThursday(d) : timeThursday.ceil(d);
  return pad2(d.getFullYear() % 1e4, p, 4);
}
function formatZone(d) {
  var z = d.getTimezoneOffset();
  return (z > 0 ? "-" : (z *= -1, "+")) + pad2(z / 60 | 0, "0", 2) + pad2(z % 60, "0", 2);
}
function formatUTCDayOfMonth(d, p) {
  return pad2(d.getUTCDate(), p, 2);
}
function formatUTCHour24(d, p) {
  return pad2(d.getUTCHours(), p, 2);
}
function formatUTCHour12(d, p) {
  return pad2(d.getUTCHours() % 12 || 12, p, 2);
}
function formatUTCDayOfYear(d, p) {
  return pad2(1 + utcDay.count(utcYear(d), d), p, 3);
}
function formatUTCMilliseconds(d, p) {
  return pad2(d.getUTCMilliseconds(), p, 3);
}
function formatUTCMicroseconds(d, p) {
  return formatUTCMilliseconds(d, p) + "000";
}
function formatUTCMonthNumber(d, p) {
  return pad2(d.getUTCMonth() + 1, p, 2);
}
function formatUTCMinutes(d, p) {
  return pad2(d.getUTCMinutes(), p, 2);
}
function formatUTCSeconds(d, p) {
  return pad2(d.getUTCSeconds(), p, 2);
}
function formatUTCWeekdayNumberMonday(d) {
  var dow = d.getUTCDay();
  return dow === 0 ? 7 : dow;
}
function formatUTCWeekNumberSunday(d, p) {
  return pad2(utcSunday.count(utcYear(d) - 1, d), p, 2);
}
function UTCdISO(d) {
  var day = d.getUTCDay();
  return day >= 4 || day === 0 ? utcThursday(d) : utcThursday.ceil(d);
}
function formatUTCWeekNumberISO(d, p) {
  d = UTCdISO(d);
  return pad2(utcThursday.count(utcYear(d), d) + (utcYear(d).getUTCDay() === 4), p, 2);
}
function formatUTCWeekdayNumberSunday(d) {
  return d.getUTCDay();
}
function formatUTCWeekNumberMonday(d, p) {
  return pad2(utcMonday.count(utcYear(d) - 1, d), p, 2);
}
function formatUTCYear(d, p) {
  return pad2(d.getUTCFullYear() % 100, p, 2);
}
function formatUTCYearISO(d, p) {
  d = UTCdISO(d);
  return pad2(d.getUTCFullYear() % 100, p, 2);
}
function formatUTCFullYear(d, p) {
  return pad2(d.getUTCFullYear() % 1e4, p, 4);
}
function formatUTCFullYearISO(d, p) {
  var day = d.getUTCDay();
  d = day >= 4 || day === 0 ? utcThursday(d) : utcThursday.ceil(d);
  return pad2(d.getUTCFullYear() % 1e4, p, 4);
}
function formatUTCZone() {
  return "+0000";
}
function formatLiteralPercent() {
  return "%";
}
function formatUnixTimestamp(d) {
  return +d;
}
function formatUnixTimestampSeconds(d) {
  return Math.floor(+d / 1e3);
}

// node_modules/d3-time-format/src/defaultLocale.js
var locale2;
var timeFormat;
var timeParse;
var utcFormat;
var utcParse;
defaultLocale2({
  dateTime: "%x, %X",
  date: "%-m/%-d/%Y",
  time: "%-I:%M:%S %p",
  periods: ["AM", "PM"],
  days: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
  shortDays: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
  months: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
  shortMonths: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
});
function defaultLocale2(definition) {
  locale2 = formatLocale(definition);
  timeFormat = locale2.format;
  timeParse = locale2.parse;
  utcFormat = locale2.utcFormat;
  utcParse = locale2.utcParse;
  return locale2;
}

// node_modules/d3-time-format/src/isoFormat.js
var isoSpecifier = "%Y-%m-%dT%H:%M:%S.%LZ";
function formatIsoNative(date2) {
  return date2.toISOString();
}
var formatIso = Date.prototype.toISOString ? formatIsoNative : utcFormat(isoSpecifier);

// node_modules/d3-time-format/src/isoParse.js
function parseIsoNative(string2) {
  var date2 = new Date(string2);
  return isNaN(date2) ? null : date2;
}
var parseIso = +/* @__PURE__ */ new Date("2000-01-01T00:00:00.000Z") ? parseIsoNative : utcParse(isoSpecifier);

// node_modules/d3-scale/src/time.js
function date(t) {
  return new Date(t);
}
function number4(t) {
  return t instanceof Date ? +t : +/* @__PURE__ */ new Date(+t);
}
function calendar(ticks2, tickInterval, year, month, week, day, hour, minute, second3, format3) {
  var scale3 = continuous(), invert = scale3.invert, domain = scale3.domain;
  var formatMillisecond = format3(".%L"), formatSecond = format3(":%S"), formatMinute = format3("%I:%M"), formatHour = format3("%I %p"), formatDay = format3("%a %d"), formatWeek = format3("%b %d"), formatMonth2 = format3("%B"), formatYear4 = format3("%Y");
  function tickFormat2(date2) {
    return (second3(date2) < date2 ? formatMillisecond : minute(date2) < date2 ? formatSecond : hour(date2) < date2 ? formatMinute : day(date2) < date2 ? formatHour : month(date2) < date2 ? week(date2) < date2 ? formatDay : formatWeek : year(date2) < date2 ? formatMonth2 : formatYear4)(date2);
  }
  scale3.invert = function(y3) {
    return new Date(invert(y3));
  };
  scale3.domain = function(_) {
    return arguments.length ? domain(Array.from(_, number4)) : domain().map(date);
  };
  scale3.ticks = function(interval2) {
    var d = domain();
    return ticks2(d[0], d[d.length - 1], interval2 == null ? 10 : interval2);
  };
  scale3.tickFormat = function(count3, specifier) {
    return specifier == null ? tickFormat2 : format3(specifier);
  };
  scale3.nice = function(interval2) {
    var d = domain();
    if (!interval2 || typeof interval2.range !== "function") interval2 = tickInterval(d[0], d[d.length - 1], interval2 == null ? 10 : interval2);
    return interval2 ? domain(nice2(d, interval2)) : scale3;
  };
  scale3.copy = function() {
    return copy(scale3, calendar(ticks2, tickInterval, year, month, week, day, hour, minute, second3, format3));
  };
  return scale3;
}
function time() {
  return initRange.apply(calendar(timeTicks, timeTickInterval, timeYear, timeMonth, timeSunday, timeDay, timeHour, timeMinute, second, timeFormat).domain([new Date(2e3, 0, 1), new Date(2e3, 0, 2)]), arguments);
}

// node_modules/d3-scale/src/utcTime.js
function utcTime() {
  return initRange.apply(calendar(utcTicks, utcTickInterval, utcYear, utcMonth, utcSunday, utcDay, utcHour, utcMinute, second, utcFormat).domain([Date.UTC(2e3, 0, 1), Date.UTC(2e3, 0, 2)]), arguments);
}

// node_modules/d3-scale/src/sequential.js
function copy2(source, target) {
  return target.domain(source.domain()).interpolator(source.interpolator()).clamp(source.clamp()).unknown(source.unknown());
}

// node_modules/d3-scale/src/diverging.js
function transformer3() {
  var x06 = 0, x12 = 0.5, x22 = 1, s2 = 1, t03, t13, t22, k10, k21, interpolator = identity3, transform2, clamp = false, unknown;
  function scale3(x3) {
    return isNaN(x3 = +x3) ? unknown : (x3 = 0.5 + ((x3 = +transform2(x3)) - t13) * (s2 * x3 < s2 * t13 ? k10 : k21), interpolator(clamp ? Math.max(0, Math.min(1, x3)) : x3));
  }
  scale3.domain = function(_) {
    return arguments.length ? ([x06, x12, x22] = _, t03 = transform2(x06 = +x06), t13 = transform2(x12 = +x12), t22 = transform2(x22 = +x22), k10 = t03 === t13 ? 0 : 0.5 / (t13 - t03), k21 = t13 === t22 ? 0 : 0.5 / (t22 - t13), s2 = t13 < t03 ? -1 : 1, scale3) : [x06, x12, x22];
  };
  scale3.clamp = function(_) {
    return arguments.length ? (clamp = !!_, scale3) : clamp;
  };
  scale3.interpolator = function(_) {
    return arguments.length ? (interpolator = _, scale3) : interpolator;
  };
  function range3(interpolate) {
    return function(_) {
      var r0, r1, r2;
      return arguments.length ? ([r0, r1, r2] = _, interpolator = piecewise(interpolate, [r0, r1, r2]), scale3) : [interpolator(0), interpolator(0.5), interpolator(1)];
    };
  }
  scale3.range = range3(value_default);
  scale3.rangeRound = range3(round_default);
  scale3.unknown = function(_) {
    return arguments.length ? (unknown = _, scale3) : unknown;
  };
  return function(t) {
    transform2 = t, t03 = t(x06), t13 = t(x12), t22 = t(x22), k10 = t03 === t13 ? 0 : 0.5 / (t13 - t03), k21 = t13 === t22 ? 0 : 0.5 / (t22 - t13), s2 = t13 < t03 ? -1 : 1;
    return scale3;
  };
}
function diverging() {
  var scale3 = linearish(transformer3()(identity3));
  scale3.copy = function() {
    return copy2(scale3, diverging());
  };
  return initInterpolator.apply(scale3, arguments);
}
function divergingLog() {
  var scale3 = loggish(transformer3()).domain([0.1, 1, 10]);
  scale3.copy = function() {
    return copy2(scale3, divergingLog()).base(scale3.base());
  };
  return initInterpolator.apply(scale3, arguments);
}
function divergingSymlog() {
  var scale3 = symlogish(transformer3());
  scale3.copy = function() {
    return copy2(scale3, divergingSymlog()).constant(scale3.constant());
  };
  return initInterpolator.apply(scale3, arguments);
}
function divergingPow() {
  var scale3 = powish(transformer3());
  scale3.copy = function() {
    return copy2(scale3, divergingPow()).exponent(scale3.exponent());
  };
  return initInterpolator.apply(scale3, arguments);
}

// node_modules/d3-scale-chromatic/src/colors.js
function colors_default(specifier) {
  var n = specifier.length / 6 | 0, colors = new Array(n), i = 0;
  while (i < n) colors[i] = "#" + specifier.slice(i * 6, ++i * 6);
  return colors;
}

// node_modules/d3-scale-chromatic/src/categorical/category10.js
var category10_default = colors_default("1f77b4ff7f0e2ca02cd627289467bd8c564be377c27f7f7fbcbd2217becf");

// node_modules/d3-scale-chromatic/src/categorical/Accent.js
var Accent_default = colors_default("7fc97fbeaed4fdc086ffff99386cb0f0027fbf5b17666666");

// node_modules/d3-scale-chromatic/src/categorical/Dark2.js
var Dark2_default = colors_default("1b9e77d95f027570b3e7298a66a61ee6ab02a6761d666666");

// node_modules/d3-scale-chromatic/src/categorical/observable10.js
var observable10_default = colors_default("4269d0efb118ff725c6cc5b03ca951ff8ab7a463f297bbf59c6b4e9498a0");

// node_modules/d3-scale-chromatic/src/categorical/Paired.js
var Paired_default = colors_default("a6cee31f78b4b2df8a33a02cfb9a99e31a1cfdbf6fff7f00cab2d66a3d9affff99b15928");

// node_modules/d3-scale-chromatic/src/categorical/Pastel1.js
var Pastel1_default = colors_default("fbb4aeb3cde3ccebc5decbe4fed9a6ffffcce5d8bdfddaecf2f2f2");

// node_modules/d3-scale-chromatic/src/categorical/Pastel2.js
var Pastel2_default = colors_default("b3e2cdfdcdaccbd5e8f4cae4e6f5c9fff2aef1e2cccccccc");

// node_modules/d3-scale-chromatic/src/categorical/Set1.js
var Set1_default = colors_default("e41a1c377eb84daf4a984ea3ff7f00ffff33a65628f781bf999999");

// node_modules/d3-scale-chromatic/src/categorical/Set2.js
var Set2_default = colors_default("66c2a5fc8d628da0cbe78ac3a6d854ffd92fe5c494b3b3b3");

// node_modules/d3-scale-chromatic/src/categorical/Set3.js
var Set3_default = colors_default("8dd3c7ffffb3bebadafb807280b1d3fdb462b3de69fccde5d9d9d9bc80bdccebc5ffed6f");

// node_modules/d3-scale-chromatic/src/categorical/Tableau10.js
var Tableau10_default = colors_default("4e79a7f28e2ce1575976b7b259a14fedc949af7aa1ff9da79c755fbab0ab");

// node_modules/d3-scale-chromatic/src/ramp.js
var ramp_default = (scheme28) => rgbBasis(scheme28[scheme28.length - 1]);

// node_modules/d3-scale-chromatic/src/diverging/BrBG.js
var scheme = new Array(3).concat(
  "d8b365f5f5f55ab4ac",
  "a6611adfc27d80cdc1018571",
  "a6611adfc27df5f5f580cdc1018571",
  "8c510ad8b365f6e8c3c7eae55ab4ac01665e",
  "8c510ad8b365f6e8c3f5f5f5c7eae55ab4ac01665e",
  "8c510abf812ddfc27df6e8c3c7eae580cdc135978f01665e",
  "8c510abf812ddfc27df6e8c3f5f5f5c7eae580cdc135978f01665e",
  "5430058c510abf812ddfc27df6e8c3c7eae580cdc135978f01665e003c30",
  "5430058c510abf812ddfc27df6e8c3f5f5f5c7eae580cdc135978f01665e003c30"
).map(colors_default);
var BrBG_default = ramp_default(scheme);

// node_modules/d3-scale-chromatic/src/diverging/PRGn.js
var scheme2 = new Array(3).concat(
  "af8dc3f7f7f77fbf7b",
  "7b3294c2a5cfa6dba0008837",
  "7b3294c2a5cff7f7f7a6dba0008837",
  "762a83af8dc3e7d4e8d9f0d37fbf7b1b7837",
  "762a83af8dc3e7d4e8f7f7f7d9f0d37fbf7b1b7837",
  "762a839970abc2a5cfe7d4e8d9f0d3a6dba05aae611b7837",
  "762a839970abc2a5cfe7d4e8f7f7f7d9f0d3a6dba05aae611b7837",
  "40004b762a839970abc2a5cfe7d4e8d9f0d3a6dba05aae611b783700441b",
  "40004b762a839970abc2a5cfe7d4e8f7f7f7d9f0d3a6dba05aae611b783700441b"
).map(colors_default);
var PRGn_default = ramp_default(scheme2);

// node_modules/d3-scale-chromatic/src/diverging/PiYG.js
var scheme3 = new Array(3).concat(
  "e9a3c9f7f7f7a1d76a",
  "d01c8bf1b6dab8e1864dac26",
  "d01c8bf1b6daf7f7f7b8e1864dac26",
  "c51b7de9a3c9fde0efe6f5d0a1d76a4d9221",
  "c51b7de9a3c9fde0eff7f7f7e6f5d0a1d76a4d9221",
  "c51b7dde77aef1b6dafde0efe6f5d0b8e1867fbc414d9221",
  "c51b7dde77aef1b6dafde0eff7f7f7e6f5d0b8e1867fbc414d9221",
  "8e0152c51b7dde77aef1b6dafde0efe6f5d0b8e1867fbc414d9221276419",
  "8e0152c51b7dde77aef1b6dafde0eff7f7f7e6f5d0b8e1867fbc414d9221276419"
).map(colors_default);
var PiYG_default = ramp_default(scheme3);

// node_modules/d3-scale-chromatic/src/diverging/PuOr.js
var scheme4 = new Array(3).concat(
  "998ec3f7f7f7f1a340",
  "5e3c99b2abd2fdb863e66101",
  "5e3c99b2abd2f7f7f7fdb863e66101",
  "542788998ec3d8daebfee0b6f1a340b35806",
  "542788998ec3d8daebf7f7f7fee0b6f1a340b35806",
  "5427888073acb2abd2d8daebfee0b6fdb863e08214b35806",
  "5427888073acb2abd2d8daebf7f7f7fee0b6fdb863e08214b35806",
  "2d004b5427888073acb2abd2d8daebfee0b6fdb863e08214b358067f3b08",
  "2d004b5427888073acb2abd2d8daebf7f7f7fee0b6fdb863e08214b358067f3b08"
).map(colors_default);
var PuOr_default = ramp_default(scheme4);

// node_modules/d3-scale-chromatic/src/diverging/RdBu.js
var scheme5 = new Array(3).concat(
  "ef8a62f7f7f767a9cf",
  "ca0020f4a58292c5de0571b0",
  "ca0020f4a582f7f7f792c5de0571b0",
  "b2182bef8a62fddbc7d1e5f067a9cf2166ac",
  "b2182bef8a62fddbc7f7f7f7d1e5f067a9cf2166ac",
  "b2182bd6604df4a582fddbc7d1e5f092c5de4393c32166ac",
  "b2182bd6604df4a582fddbc7f7f7f7d1e5f092c5de4393c32166ac",
  "67001fb2182bd6604df4a582fddbc7d1e5f092c5de4393c32166ac053061",
  "67001fb2182bd6604df4a582fddbc7f7f7f7d1e5f092c5de4393c32166ac053061"
).map(colors_default);
var RdBu_default = ramp_default(scheme5);

// node_modules/d3-scale-chromatic/src/diverging/RdGy.js
var scheme6 = new Array(3).concat(
  "ef8a62ffffff999999",
  "ca0020f4a582bababa404040",
  "ca0020f4a582ffffffbababa404040",
  "b2182bef8a62fddbc7e0e0e09999994d4d4d",
  "b2182bef8a62fddbc7ffffffe0e0e09999994d4d4d",
  "b2182bd6604df4a582fddbc7e0e0e0bababa8787874d4d4d",
  "b2182bd6604df4a582fddbc7ffffffe0e0e0bababa8787874d4d4d",
  "67001fb2182bd6604df4a582fddbc7e0e0e0bababa8787874d4d4d1a1a1a",
  "67001fb2182bd6604df4a582fddbc7ffffffe0e0e0bababa8787874d4d4d1a1a1a"
).map(colors_default);
var RdGy_default = ramp_default(scheme6);

// node_modules/d3-scale-chromatic/src/diverging/RdYlBu.js
var scheme7 = new Array(3).concat(
  "fc8d59ffffbf91bfdb",
  "d7191cfdae61abd9e92c7bb6",
  "d7191cfdae61ffffbfabd9e92c7bb6",
  "d73027fc8d59fee090e0f3f891bfdb4575b4",
  "d73027fc8d59fee090ffffbfe0f3f891bfdb4575b4",
  "d73027f46d43fdae61fee090e0f3f8abd9e974add14575b4",
  "d73027f46d43fdae61fee090ffffbfe0f3f8abd9e974add14575b4",
  "a50026d73027f46d43fdae61fee090e0f3f8abd9e974add14575b4313695",
  "a50026d73027f46d43fdae61fee090ffffbfe0f3f8abd9e974add14575b4313695"
).map(colors_default);
var RdYlBu_default = ramp_default(scheme7);

// node_modules/d3-scale-chromatic/src/diverging/RdYlGn.js
var scheme8 = new Array(3).concat(
  "fc8d59ffffbf91cf60",
  "d7191cfdae61a6d96a1a9641",
  "d7191cfdae61ffffbfa6d96a1a9641",
  "d73027fc8d59fee08bd9ef8b91cf601a9850",
  "d73027fc8d59fee08bffffbfd9ef8b91cf601a9850",
  "d73027f46d43fdae61fee08bd9ef8ba6d96a66bd631a9850",
  "d73027f46d43fdae61fee08bffffbfd9ef8ba6d96a66bd631a9850",
  "a50026d73027f46d43fdae61fee08bd9ef8ba6d96a66bd631a9850006837",
  "a50026d73027f46d43fdae61fee08bffffbfd9ef8ba6d96a66bd631a9850006837"
).map(colors_default);
var RdYlGn_default = ramp_default(scheme8);

// node_modules/d3-scale-chromatic/src/diverging/Spectral.js
var scheme9 = new Array(3).concat(
  "fc8d59ffffbf99d594",
  "d7191cfdae61abdda42b83ba",
  "d7191cfdae61ffffbfabdda42b83ba",
  "d53e4ffc8d59fee08be6f59899d5943288bd",
  "d53e4ffc8d59fee08bffffbfe6f59899d5943288bd",
  "d53e4ff46d43fdae61fee08be6f598abdda466c2a53288bd",
  "d53e4ff46d43fdae61fee08bffffbfe6f598abdda466c2a53288bd",
  "9e0142d53e4ff46d43fdae61fee08be6f598abdda466c2a53288bd5e4fa2",
  "9e0142d53e4ff46d43fdae61fee08bffffbfe6f598abdda466c2a53288bd5e4fa2"
).map(colors_default);
var Spectral_default = ramp_default(scheme9);

// node_modules/d3-scale-chromatic/src/sequential-multi/BuGn.js
var scheme10 = new Array(3).concat(
  "e5f5f999d8c92ca25f",
  "edf8fbb2e2e266c2a4238b45",
  "edf8fbb2e2e266c2a42ca25f006d2c",
  "edf8fbccece699d8c966c2a42ca25f006d2c",
  "edf8fbccece699d8c966c2a441ae76238b45005824",
  "f7fcfde5f5f9ccece699d8c966c2a441ae76238b45005824",
  "f7fcfde5f5f9ccece699d8c966c2a441ae76238b45006d2c00441b"
).map(colors_default);
var BuGn_default = ramp_default(scheme10);

// node_modules/d3-scale-chromatic/src/sequential-multi/BuPu.js
var scheme11 = new Array(3).concat(
  "e0ecf49ebcda8856a7",
  "edf8fbb3cde38c96c688419d",
  "edf8fbb3cde38c96c68856a7810f7c",
  "edf8fbbfd3e69ebcda8c96c68856a7810f7c",
  "edf8fbbfd3e69ebcda8c96c68c6bb188419d6e016b",
  "f7fcfde0ecf4bfd3e69ebcda8c96c68c6bb188419d6e016b",
  "f7fcfde0ecf4bfd3e69ebcda8c96c68c6bb188419d810f7c4d004b"
).map(colors_default);
var BuPu_default = ramp_default(scheme11);

// node_modules/d3-scale-chromatic/src/sequential-multi/GnBu.js
var scheme12 = new Array(3).concat(
  "e0f3dba8ddb543a2ca",
  "f0f9e8bae4bc7bccc42b8cbe",
  "f0f9e8bae4bc7bccc443a2ca0868ac",
  "f0f9e8ccebc5a8ddb57bccc443a2ca0868ac",
  "f0f9e8ccebc5a8ddb57bccc44eb3d32b8cbe08589e",
  "f7fcf0e0f3dbccebc5a8ddb57bccc44eb3d32b8cbe08589e",
  "f7fcf0e0f3dbccebc5a8ddb57bccc44eb3d32b8cbe0868ac084081"
).map(colors_default);
var GnBu_default = ramp_default(scheme12);

// node_modules/d3-scale-chromatic/src/sequential-multi/OrRd.js
var scheme13 = new Array(3).concat(
  "fee8c8fdbb84e34a33",
  "fef0d9fdcc8afc8d59d7301f",
  "fef0d9fdcc8afc8d59e34a33b30000",
  "fef0d9fdd49efdbb84fc8d59e34a33b30000",
  "fef0d9fdd49efdbb84fc8d59ef6548d7301f990000",
  "fff7ecfee8c8fdd49efdbb84fc8d59ef6548d7301f990000",
  "fff7ecfee8c8fdd49efdbb84fc8d59ef6548d7301fb300007f0000"
).map(colors_default);
var OrRd_default = ramp_default(scheme13);

// node_modules/d3-scale-chromatic/src/sequential-multi/PuBuGn.js
var scheme14 = new Array(3).concat(
  "ece2f0a6bddb1c9099",
  "f6eff7bdc9e167a9cf02818a",
  "f6eff7bdc9e167a9cf1c9099016c59",
  "f6eff7d0d1e6a6bddb67a9cf1c9099016c59",
  "f6eff7d0d1e6a6bddb67a9cf3690c002818a016450",
  "fff7fbece2f0d0d1e6a6bddb67a9cf3690c002818a016450",
  "fff7fbece2f0d0d1e6a6bddb67a9cf3690c002818a016c59014636"
).map(colors_default);
var PuBuGn_default = ramp_default(scheme14);

// node_modules/d3-scale-chromatic/src/sequential-multi/PuBu.js
var scheme15 = new Array(3).concat(
  "ece7f2a6bddb2b8cbe",
  "f1eef6bdc9e174a9cf0570b0",
  "f1eef6bdc9e174a9cf2b8cbe045a8d",
  "f1eef6d0d1e6a6bddb74a9cf2b8cbe045a8d",
  "f1eef6d0d1e6a6bddb74a9cf3690c00570b0034e7b",
  "fff7fbece7f2d0d1e6a6bddb74a9cf3690c00570b0034e7b",
  "fff7fbece7f2d0d1e6a6bddb74a9cf3690c00570b0045a8d023858"
).map(colors_default);
var PuBu_default = ramp_default(scheme15);

// node_modules/d3-scale-chromatic/src/sequential-multi/PuRd.js
var scheme16 = new Array(3).concat(
  "e7e1efc994c7dd1c77",
  "f1eef6d7b5d8df65b0ce1256",
  "f1eef6d7b5d8df65b0dd1c77980043",
  "f1eef6d4b9dac994c7df65b0dd1c77980043",
  "f1eef6d4b9dac994c7df65b0e7298ace125691003f",
  "f7f4f9e7e1efd4b9dac994c7df65b0e7298ace125691003f",
  "f7f4f9e7e1efd4b9dac994c7df65b0e7298ace125698004367001f"
).map(colors_default);
var PuRd_default = ramp_default(scheme16);

// node_modules/d3-scale-chromatic/src/sequential-multi/RdPu.js
var scheme17 = new Array(3).concat(
  "fde0ddfa9fb5c51b8a",
  "feebe2fbb4b9f768a1ae017e",
  "feebe2fbb4b9f768a1c51b8a7a0177",
  "feebe2fcc5c0fa9fb5f768a1c51b8a7a0177",
  "feebe2fcc5c0fa9fb5f768a1dd3497ae017e7a0177",
  "fff7f3fde0ddfcc5c0fa9fb5f768a1dd3497ae017e7a0177",
  "fff7f3fde0ddfcc5c0fa9fb5f768a1dd3497ae017e7a017749006a"
).map(colors_default);
var RdPu_default = ramp_default(scheme17);

// node_modules/d3-scale-chromatic/src/sequential-multi/YlGnBu.js
var scheme18 = new Array(3).concat(
  "edf8b17fcdbb2c7fb8",
  "ffffcca1dab441b6c4225ea8",
  "ffffcca1dab441b6c42c7fb8253494",
  "ffffccc7e9b47fcdbb41b6c42c7fb8253494",
  "ffffccc7e9b47fcdbb41b6c41d91c0225ea80c2c84",
  "ffffd9edf8b1c7e9b47fcdbb41b6c41d91c0225ea80c2c84",
  "ffffd9edf8b1c7e9b47fcdbb41b6c41d91c0225ea8253494081d58"
).map(colors_default);
var YlGnBu_default = ramp_default(scheme18);

// node_modules/d3-scale-chromatic/src/sequential-multi/YlGn.js
var scheme19 = new Array(3).concat(
  "f7fcb9addd8e31a354",
  "ffffccc2e69978c679238443",
  "ffffccc2e69978c67931a354006837",
  "ffffccd9f0a3addd8e78c67931a354006837",
  "ffffccd9f0a3addd8e78c67941ab5d238443005a32",
  "ffffe5f7fcb9d9f0a3addd8e78c67941ab5d238443005a32",
  "ffffe5f7fcb9d9f0a3addd8e78c67941ab5d238443006837004529"
).map(colors_default);
var YlGn_default = ramp_default(scheme19);

// node_modules/d3-scale-chromatic/src/sequential-multi/YlOrBr.js
var scheme20 = new Array(3).concat(
  "fff7bcfec44fd95f0e",
  "ffffd4fed98efe9929cc4c02",
  "ffffd4fed98efe9929d95f0e993404",
  "ffffd4fee391fec44ffe9929d95f0e993404",
  "ffffd4fee391fec44ffe9929ec7014cc4c028c2d04",
  "ffffe5fff7bcfee391fec44ffe9929ec7014cc4c028c2d04",
  "ffffe5fff7bcfee391fec44ffe9929ec7014cc4c02993404662506"
).map(colors_default);
var YlOrBr_default = ramp_default(scheme20);

// node_modules/d3-scale-chromatic/src/sequential-multi/YlOrRd.js
var scheme21 = new Array(3).concat(
  "ffeda0feb24cf03b20",
  "ffffb2fecc5cfd8d3ce31a1c",
  "ffffb2fecc5cfd8d3cf03b20bd0026",
  "ffffb2fed976feb24cfd8d3cf03b20bd0026",
  "ffffb2fed976feb24cfd8d3cfc4e2ae31a1cb10026",
  "ffffccffeda0fed976feb24cfd8d3cfc4e2ae31a1cb10026",
  "ffffccffeda0fed976feb24cfd8d3cfc4e2ae31a1cbd0026800026"
).map(colors_default);
var YlOrRd_default = ramp_default(scheme21);

// node_modules/d3-scale-chromatic/src/sequential-single/Blues.js
var scheme22 = new Array(3).concat(
  "deebf79ecae13182bd",
  "eff3ffbdd7e76baed62171b5",
  "eff3ffbdd7e76baed63182bd08519c",
  "eff3ffc6dbef9ecae16baed63182bd08519c",
  "eff3ffc6dbef9ecae16baed64292c62171b5084594",
  "f7fbffdeebf7c6dbef9ecae16baed64292c62171b5084594",
  "f7fbffdeebf7c6dbef9ecae16baed64292c62171b508519c08306b"
).map(colors_default);
var Blues_default = ramp_default(scheme22);

// node_modules/d3-scale-chromatic/src/sequential-single/Greens.js
var scheme23 = new Array(3).concat(
  "e5f5e0a1d99b31a354",
  "edf8e9bae4b374c476238b45",
  "edf8e9bae4b374c47631a354006d2c",
  "edf8e9c7e9c0a1d99b74c47631a354006d2c",
  "edf8e9c7e9c0a1d99b74c47641ab5d238b45005a32",
  "f7fcf5e5f5e0c7e9c0a1d99b74c47641ab5d238b45005a32",
  "f7fcf5e5f5e0c7e9c0a1d99b74c47641ab5d238b45006d2c00441b"
).map(colors_default);
var Greens_default = ramp_default(scheme23);

// node_modules/d3-scale-chromatic/src/sequential-single/Greys.js
var scheme24 = new Array(3).concat(
  "f0f0f0bdbdbd636363",
  "f7f7f7cccccc969696525252",
  "f7f7f7cccccc969696636363252525",
  "f7f7f7d9d9d9bdbdbd969696636363252525",
  "f7f7f7d9d9d9bdbdbd969696737373525252252525",
  "fffffff0f0f0d9d9d9bdbdbd969696737373525252252525",
  "fffffff0f0f0d9d9d9bdbdbd969696737373525252252525000000"
).map(colors_default);
var Greys_default = ramp_default(scheme24);

// node_modules/d3-scale-chromatic/src/sequential-single/Purples.js
var scheme25 = new Array(3).concat(
  "efedf5bcbddc756bb1",
  "f2f0f7cbc9e29e9ac86a51a3",
  "f2f0f7cbc9e29e9ac8756bb154278f",
  "f2f0f7dadaebbcbddc9e9ac8756bb154278f",
  "f2f0f7dadaebbcbddc9e9ac8807dba6a51a34a1486",
  "fcfbfdefedf5dadaebbcbddc9e9ac8807dba6a51a34a1486",
  "fcfbfdefedf5dadaebbcbddc9e9ac8807dba6a51a354278f3f007d"
).map(colors_default);
var Purples_default = ramp_default(scheme25);

// node_modules/d3-scale-chromatic/src/sequential-single/Reds.js
var scheme26 = new Array(3).concat(
  "fee0d2fc9272de2d26",
  "fee5d9fcae91fb6a4acb181d",
  "fee5d9fcae91fb6a4ade2d26a50f15",
  "fee5d9fcbba1fc9272fb6a4ade2d26a50f15",
  "fee5d9fcbba1fc9272fb6a4aef3b2ccb181d99000d",
  "fff5f0fee0d2fcbba1fc9272fb6a4aef3b2ccb181d99000d",
  "fff5f0fee0d2fcbba1fc9272fb6a4aef3b2ccb181da50f1567000d"
).map(colors_default);
var Reds_default = ramp_default(scheme26);

// node_modules/d3-scale-chromatic/src/sequential-single/Oranges.js
var scheme27 = new Array(3).concat(
  "fee6cefdae6be6550d",
  "feeddefdbe85fd8d3cd94701",
  "feeddefdbe85fd8d3ce6550da63603",
  "feeddefdd0a2fdae6bfd8d3ce6550da63603",
  "feeddefdd0a2fdae6bfd8d3cf16913d948018c2d04",
  "fff5ebfee6cefdd0a2fdae6bfd8d3cf16913d948018c2d04",
  "fff5ebfee6cefdd0a2fdae6bfd8d3cf16913d94801a636037f2704"
).map(colors_default);
var Oranges_default = ramp_default(scheme27);

// node_modules/d3-scale-chromatic/src/sequential-multi/cividis.js
function cividis_default(t) {
  t = Math.max(0, Math.min(1, t));
  return "rgb(" + Math.max(0, Math.min(255, Math.round(-4.54 - t * (35.34 - t * (2381.73 - t * (6402.7 - t * (7024.72 - t * 2710.57))))))) + ", " + Math.max(0, Math.min(255, Math.round(32.49 + t * (170.73 + t * (52.82 - t * (131.46 - t * (176.58 - t * 67.37))))))) + ", " + Math.max(0, Math.min(255, Math.round(81.24 + t * (442.36 - t * (2482.43 - t * (6167.24 - t * (6614.94 - t * 2475.67))))))) + ")";
}

// node_modules/d3-scale-chromatic/src/sequential-multi/cubehelix.js
var cubehelix_default2 = cubehelixLong(cubehelix(300, 0.5, 0), cubehelix(-240, 0.5, 1));

// node_modules/d3-scale-chromatic/src/sequential-multi/rainbow.js
var warm = cubehelixLong(cubehelix(-100, 0.75, 0.35), cubehelix(80, 1.5, 0.8));
var cool = cubehelixLong(cubehelix(260, 0.75, 0.35), cubehelix(80, 1.5, 0.8));
var c = cubehelix();
function rainbow_default(t) {
  if (t < 0 || t > 1) t -= Math.floor(t);
  var ts = Math.abs(t - 0.5);
  c.h = 360 * t - 100;
  c.s = 1.5 - 1.5 * ts;
  c.l = 0.8 - 0.9 * ts;
  return c + "";
}

// node_modules/d3-scale-chromatic/src/sequential-multi/sinebow.js
var c2 = rgb();
var pi_1_3 = Math.PI / 3;
var pi_2_3 = Math.PI * 2 / 3;
function sinebow_default(t) {
  var x3;
  t = (0.5 - t) * Math.PI;
  c2.r = 255 * (x3 = Math.sin(t)) * x3;
  c2.g = 255 * (x3 = Math.sin(t + pi_1_3)) * x3;
  c2.b = 255 * (x3 = Math.sin(t + pi_2_3)) * x3;
  return c2 + "";
}

// node_modules/d3-scale-chromatic/src/sequential-multi/turbo.js
function turbo_default(t) {
  t = Math.max(0, Math.min(1, t));
  return "rgb(" + Math.max(0, Math.min(255, Math.round(34.61 + t * (1172.33 - t * (10793.56 - t * (33300.12 - t * (38394.49 - t * 14825.05))))))) + ", " + Math.max(0, Math.min(255, Math.round(23.31 + t * (557.33 + t * (1225.33 - t * (3574.96 - t * (1073.77 + t * 707.56))))))) + ", " + Math.max(0, Math.min(255, Math.round(27.2 + t * (3211.1 - t * (15327.97 - t * (27814 - t * (22569.18 - t * 6838.66))))))) + ")";
}

// node_modules/d3-scale-chromatic/src/sequential-multi/viridis.js
function ramp(range3) {
  var n = range3.length;
  return function(t) {
    return range3[Math.max(0, Math.min(n - 1, Math.floor(t * n)))];
  };
}
var viridis_default = ramp(colors_default("44015444025645045745055946075a46085c460a5d460b5e470d60470e6147106347116447136548146748166848176948186a481a6c481b6d481c6e481d6f481f70482071482173482374482475482576482677482878482979472a7a472c7a472d7b472e7c472f7d46307e46327e46337f463480453581453781453882443983443a83443b84433d84433e85423f854240864241864142874144874045884046883f47883f48893e49893e4a893e4c8a3d4d8a3d4e8a3c4f8a3c508b3b518b3b528b3a538b3a548c39558c39568c38588c38598c375a8c375b8d365c8d365d8d355e8d355f8d34608d34618d33628d33638d32648e32658e31668e31678e31688e30698e306a8e2f6b8e2f6c8e2e6d8e2e6e8e2e6f8e2d708e2d718e2c718e2c728e2c738e2b748e2b758e2a768e2a778e2a788e29798e297a8e297b8e287c8e287d8e277e8e277f8e27808e26818e26828e26828e25838e25848e25858e24868e24878e23888e23898e238a8d228b8d228c8d228d8d218e8d218f8d21908d21918c20928c20928c20938c1f948c1f958b1f968b1f978b1f988b1f998a1f9a8a1e9b8a1e9c891e9d891f9e891f9f881fa0881fa1881fa1871fa28720a38620a48621a58521a68522a78522a88423a98324aa8325ab8225ac8226ad8127ad8128ae8029af7f2ab07f2cb17e2db27d2eb37c2fb47c31b57b32b67a34b67935b77937b87838b9773aba763bbb753dbc743fbc7340bd7242be7144bf7046c06f48c16e4ac16d4cc26c4ec36b50c46a52c56954c56856c66758c7655ac8645cc8635ec96260ca6063cb5f65cb5e67cc5c69cd5b6ccd5a6ece5870cf5773d05675d05477d1537ad1517cd2507fd34e81d34d84d44b86d54989d5488bd6468ed64590d74393d74195d84098d83e9bd93c9dd93ba0da39a2da37a5db36a8db34aadc32addc30b0dd2fb2dd2db5de2bb8de29bade28bddf26c0df25c2df23c5e021c8e020cae11fcde11dd0e11cd2e21bd5e21ad8e219dae319dde318dfe318e2e418e5e419e7e419eae51aece51befe51cf1e51df4e61ef6e620f8e621fbe723fde725"));
var magma = ramp(colors_default("00000401000501010601010802010902020b02020d03030f03031204041405041606051806051a07061c08071e0907200a08220b09240c09260d0a290e0b2b100b2d110c2f120d31130d34140e36150e38160f3b180f3d19103f1a10421c10441d11471e114920114b21114e22115024125325125527125829115a2a115c2c115f2d11612f116331116533106734106936106b38106c390f6e3b0f703d0f713f0f72400f74420f75440f764510774710784910784a10794c117a4e117b4f127b51127c52137c54137d56147d57157e59157e5a167e5c167f5d177f5f187f601880621980641a80651a80671b80681c816a1c816b1d816d1d816e1e81701f81721f817320817521817621817822817922827b23827c23827e24828025828125818326818426818627818827818928818b29818c29818e2a81902a81912b81932b80942c80962c80982d80992d809b2e7f9c2e7f9e2f7fa02f7fa1307ea3307ea5317ea6317da8327daa337dab337cad347cae347bb0357bb2357bb3367ab5367ab73779b83779ba3878bc3978bd3977bf3a77c03a76c23b75c43c75c53c74c73d73c83e73ca3e72cc3f71cd4071cf4070d0416fd2426fd3436ed5446dd6456cd8456cd9466bdb476adc4869de4968df4a68e04c67e24d66e34e65e44f64e55064e75263e85362e95462ea5661eb5760ec5860ed5a5fee5b5eef5d5ef05f5ef1605df2625df2645cf3655cf4675cf4695cf56b5cf66c5cf66e5cf7705cf7725cf8745cf8765cf9785df9795df97b5dfa7d5efa7f5efa815ffb835ffb8560fb8761fc8961fc8a62fc8c63fc8e64fc9065fd9266fd9467fd9668fd9869fd9a6afd9b6bfe9d6cfe9f6dfea16efea36ffea571fea772fea973feaa74feac76feae77feb078feb27afeb47bfeb67cfeb77efeb97ffebb81febd82febf84fec185fec287fec488fec68afec88cfeca8dfecc8ffecd90fecf92fed194fed395fed597fed799fed89afdda9cfddc9efddea0fde0a1fde2a3fde3a5fde5a7fde7a9fde9aafdebacfcecaefceeb0fcf0b2fcf2b4fcf4b6fcf6b8fcf7b9fcf9bbfcfbbdfcfdbf"));
var inferno = ramp(colors_default("00000401000501010601010802010a02020c02020e03021004031204031405041706041907051b08051d09061f0a07220b07240c08260d08290e092b10092d110a30120a32140b34150b37160b39180c3c190c3e1b0c411c0c431e0c451f0c48210c4a230c4c240c4f260c51280b53290b552b0b572d0b592f0a5b310a5c320a5e340a5f3609613809623909633b09643d09653e0966400a67420a68440a68450a69470b6a490b6a4a0c6b4c0c6b4d0d6c4f0d6c510e6c520e6d540f6d550f6d57106e59106e5a116e5c126e5d126e5f136e61136e62146e64156e65156e67166e69166e6a176e6c186e6d186e6f196e71196e721a6e741a6e751b6e771c6d781c6d7a1d6d7c1d6d7d1e6d7f1e6c801f6c82206c84206b85216b87216b88226a8a226a8c23698d23698f24699025689225689326679526679727669827669a28659b29649d29649f2a63a02a63a22b62a32c61a52c60a62d60a82e5fa92e5eab2f5ead305dae305cb0315bb1325ab3325ab43359b63458b73557b93556ba3655bc3754bd3853bf3952c03a51c13a50c33b4fc43c4ec63d4dc73e4cc83f4bca404acb4149cc4248ce4347cf4446d04545d24644d34743d44842d54a41d74b3fd84c3ed94d3dda4e3cdb503bdd513ade5238df5337e05536e15635e25734e35933e45a31e55c30e65d2fe75e2ee8602de9612bea632aeb6429eb6628ec6726ed6925ee6a24ef6c23ef6e21f06f20f1711ff1731df2741cf3761bf37819f47918f57b17f57d15f67e14f68013f78212f78410f8850ff8870ef8890cf98b0bf98c0af98e09fa9008fa9207fa9407fb9606fb9706fb9906fb9b06fb9d07fc9f07fca108fca309fca50afca60cfca80dfcaa0ffcac11fcae12fcb014fcb216fcb418fbb61afbb81dfbba1ffbbc21fbbe23fac026fac228fac42afac62df9c72ff9c932f9cb35f8cd37f8cf3af7d13df7d340f6d543f6d746f5d949f5db4cf4dd4ff4df53f4e156f3e35af3e55df2e661f2e865f2ea69f1ec6df1ed71f1ef75f1f179f2f27df2f482f3f586f3f68af4f88ef5f992f6fa96f8fb9af9fc9dfafda1fcffa4"));
var plasma = ramp(colors_default("0d088710078813078916078a19068c1b068d1d068e20068f2206902406912605912805922a05932c05942e05952f059631059733059735049837049938049a3a049a3c049b3e049c3f049c41049d43039e44039e46039f48039f4903a04b03a14c02a14e02a25002a25102a35302a35502a45601a45801a45901a55b01a55c01a65e01a66001a66100a76300a76400a76600a76700a86900a86a00a86c00a86e00a86f00a87100a87201a87401a87501a87701a87801a87a02a87b02a87d03a87e03a88004a88104a78305a78405a78606a68707a68808a68a09a58b0aa58d0ba58e0ca48f0da4910ea3920fa39410a29511a19613a19814a099159f9a169f9c179e9d189d9e199da01a9ca11b9ba21d9aa31e9aa51f99a62098a72197a82296aa2395ab2494ac2694ad2793ae2892b02991b12a90b22b8fb32c8eb42e8db52f8cb6308bb7318ab83289ba3388bb3488bc3587bd3786be3885bf3984c03a83c13b82c23c81c33d80c43e7fc5407ec6417dc7427cc8437bc9447aca457acb4679cc4778cc4977cd4a76ce4b75cf4c74d04d73d14e72d24f71d35171d45270d5536fd5546ed6556dd7566cd8576bd9586ada5a6ada5b69db5c68dc5d67dd5e66de5f65de6164df6263e06363e16462e26561e26660e3685fe4695ee56a5de56b5de66c5ce76e5be76f5ae87059e97158e97257ea7457eb7556eb7655ec7754ed7953ed7a52ee7b51ef7c51ef7e50f07f4ff0804ef1814df1834cf2844bf3854bf3874af48849f48948f58b47f58c46f68d45f68f44f79044f79143f79342f89441f89540f9973ff9983ef99a3efa9b3dfa9c3cfa9e3bfb9f3afba139fba238fca338fca537fca636fca835fca934fdab33fdac33fdae32fdaf31fdb130fdb22ffdb42ffdb52efeb72dfeb82cfeba2cfebb2bfebd2afebe2afec029fdc229fdc328fdc527fdc627fdc827fdca26fdcb26fccd25fcce25fcd025fcd225fbd324fbd524fbd724fad824fada24f9dc24f9dd25f8df25f8e125f7e225f7e425f6e626f6e826f5e926f5eb27f4ed27f3ee27f3f027f2f227f1f426f1f525f0f724f0f921"));

// node_modules/d3-shape/src/constant.js
function constant_default10(x3) {
  return function constant3() {
    return x3;
  };
}

// node_modules/d3-shape/src/math.js
var cos3 = Math.cos;
var min3 = Math.min;
var sin3 = Math.sin;
var sqrt3 = Math.sqrt;
var epsilon8 = 1e-12;
var pi5 = Math.PI;
var halfPi4 = pi5 / 2;
var tau6 = 2 * pi5;

// node_modules/d3-shape/src/path.js
function withPath(shape) {
  let digits = 3;
  shape.digits = function(_) {
    if (!arguments.length) return digits;
    if (_ == null) {
      digits = null;
    } else {
      const d = Math.floor(_);
      if (!(d >= 0)) throw new RangeError(`invalid digits: ${_}`);
      digits = d;
    }
    return shape;
  };
  return () => new Path(digits);
}

// node_modules/d3-shape/src/array.js
var slice4 = Array.prototype.slice;
function array_default3(x3) {
  return typeof x3 === "object" && "length" in x3 ? x3 : Array.from(x3);
}

// node_modules/d3-shape/src/curve/linear.js
function Linear(context) {
  this._context = context;
}
Linear.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._point = 0;
  },
  lineEnd: function() {
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._line ? this._context.lineTo(x3, y3) : this._context.moveTo(x3, y3);
        break;
      case 1:
        this._point = 2;
      // falls through
      default:
        this._context.lineTo(x3, y3);
        break;
    }
  }
};
function linear_default(context) {
  return new Linear(context);
}

// node_modules/d3-shape/src/point.js
function x2(p) {
  return p[0];
}
function y2(p) {
  return p[1];
}

// node_modules/d3-shape/src/line.js
function line_default2(x3, y3) {
  var defined2 = constant_default10(true), context = null, curve = linear_default, output = null, path2 = withPath(line2);
  x3 = typeof x3 === "function" ? x3 : x3 === void 0 ? x2 : constant_default10(x3);
  y3 = typeof y3 === "function" ? y3 : y3 === void 0 ? y2 : constant_default10(y3);
  function line2(data) {
    var i, n = (data = array_default3(data)).length, d, defined0 = false, buffer;
    if (context == null) output = curve(buffer = path2());
    for (i = 0; i <= n; ++i) {
      if (!(i < n && defined2(d = data[i], i, data)) === defined0) {
        if (defined0 = !defined0) output.lineStart();
        else output.lineEnd();
      }
      if (defined0) output.point(+x3(d, i, data), +y3(d, i, data));
    }
    if (buffer) return output = null, buffer + "" || null;
  }
  line2.x = function(_) {
    return arguments.length ? (x3 = typeof _ === "function" ? _ : constant_default10(+_), line2) : x3;
  };
  line2.y = function(_) {
    return arguments.length ? (y3 = typeof _ === "function" ? _ : constant_default10(+_), line2) : y3;
  };
  line2.defined = function(_) {
    return arguments.length ? (defined2 = typeof _ === "function" ? _ : constant_default10(!!_), line2) : defined2;
  };
  line2.curve = function(_) {
    return arguments.length ? (curve = _, context != null && (output = curve(context)), line2) : curve;
  };
  line2.context = function(_) {
    return arguments.length ? (_ == null ? context = output = null : output = curve(context = _), line2) : context;
  };
  return line2;
}

// node_modules/d3-shape/src/area.js
function area_default5(x06, y06, y12) {
  var x12 = null, defined2 = constant_default10(true), context = null, curve = linear_default, output = null, path2 = withPath(area2);
  x06 = typeof x06 === "function" ? x06 : x06 === void 0 ? x2 : constant_default10(+x06);
  y06 = typeof y06 === "function" ? y06 : y06 === void 0 ? constant_default10(0) : constant_default10(+y06);
  y12 = typeof y12 === "function" ? y12 : y12 === void 0 ? y2 : constant_default10(+y12);
  function area2(data) {
    var i, j, k2, n = (data = array_default3(data)).length, d, defined0 = false, buffer, x0z = new Array(n), y0z = new Array(n);
    if (context == null) output = curve(buffer = path2());
    for (i = 0; i <= n; ++i) {
      if (!(i < n && defined2(d = data[i], i, data)) === defined0) {
        if (defined0 = !defined0) {
          j = i;
          output.areaStart();
          output.lineStart();
        } else {
          output.lineEnd();
          output.lineStart();
          for (k2 = i - 1; k2 >= j; --k2) {
            output.point(x0z[k2], y0z[k2]);
          }
          output.lineEnd();
          output.areaEnd();
        }
      }
      if (defined0) {
        x0z[i] = +x06(d, i, data), y0z[i] = +y06(d, i, data);
        output.point(x12 ? +x12(d, i, data) : x0z[i], y12 ? +y12(d, i, data) : y0z[i]);
      }
    }
    if (buffer) return output = null, buffer + "" || null;
  }
  function arealine() {
    return line_default2().defined(defined2).curve(curve).context(context);
  }
  area2.x = function(_) {
    return arguments.length ? (x06 = typeof _ === "function" ? _ : constant_default10(+_), x12 = null, area2) : x06;
  };
  area2.x0 = function(_) {
    return arguments.length ? (x06 = typeof _ === "function" ? _ : constant_default10(+_), area2) : x06;
  };
  area2.x1 = function(_) {
    return arguments.length ? (x12 = _ == null ? null : typeof _ === "function" ? _ : constant_default10(+_), area2) : x12;
  };
  area2.y = function(_) {
    return arguments.length ? (y06 = typeof _ === "function" ? _ : constant_default10(+_), y12 = null, area2) : y06;
  };
  area2.y0 = function(_) {
    return arguments.length ? (y06 = typeof _ === "function" ? _ : constant_default10(+_), area2) : y06;
  };
  area2.y1 = function(_) {
    return arguments.length ? (y12 = _ == null ? null : typeof _ === "function" ? _ : constant_default10(+_), area2) : y12;
  };
  area2.lineX0 = area2.lineY0 = function() {
    return arealine().x(x06).y(y06);
  };
  area2.lineY1 = function() {
    return arealine().x(x06).y(y12);
  };
  area2.lineX1 = function() {
    return arealine().x(x12).y(y06);
  };
  area2.defined = function(_) {
    return arguments.length ? (defined2 = typeof _ === "function" ? _ : constant_default10(!!_), area2) : defined2;
  };
  area2.curve = function(_) {
    return arguments.length ? (curve = _, context != null && (output = curve(context)), area2) : curve;
  };
  area2.context = function(_) {
    return arguments.length ? (_ == null ? context = output = null : output = curve(context = _), area2) : context;
  };
  return area2;
}

// node_modules/d3-shape/src/curve/radial.js
var curveRadialLinear = curveRadial(linear_default);
function Radial(curve) {
  this._curve = curve;
}
Radial.prototype = {
  areaStart: function() {
    this._curve.areaStart();
  },
  areaEnd: function() {
    this._curve.areaEnd();
  },
  lineStart: function() {
    this._curve.lineStart();
  },
  lineEnd: function() {
    this._curve.lineEnd();
  },
  point: function(a2, r) {
    this._curve.point(r * Math.sin(a2), r * -Math.cos(a2));
  }
};
function curveRadial(curve) {
  function radial2(context) {
    return new Radial(curve(context));
  }
  radial2._curve = curve;
  return radial2;
}

// node_modules/d3-shape/src/curve/bump.js
var Bump = class {
  constructor(context, x3) {
    this._context = context;
    this._x = x3;
  }
  areaStart() {
    this._line = 0;
  }
  areaEnd() {
    this._line = NaN;
  }
  lineStart() {
    this._point = 0;
  }
  lineEnd() {
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    this._line = 1 - this._line;
  }
  point(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0: {
        this._point = 1;
        if (this._line) this._context.lineTo(x3, y3);
        else this._context.moveTo(x3, y3);
        break;
      }
      case 1:
        this._point = 2;
      // falls through
      default: {
        if (this._x) this._context.bezierCurveTo(this._x0 = (this._x0 + x3) / 2, this._y0, this._x0, y3, x3, y3);
        else this._context.bezierCurveTo(this._x0, this._y0 = (this._y0 + y3) / 2, x3, this._y0, x3, y3);
        break;
      }
    }
    this._x0 = x3, this._y0 = y3;
  }
};
function bumpX(context) {
  return new Bump(context, true);
}
function bumpY(context) {
  return new Bump(context, false);
}

// node_modules/d3-shape/src/symbol/asterisk.js
var sqrt32 = sqrt3(3);
var asterisk_default = {
  draw(context, size) {
    const r = sqrt3(size + min3(size / 28, 0.75)) * 0.59436;
    const t = r / 2;
    const u4 = t * sqrt32;
    context.moveTo(0, r);
    context.lineTo(0, -r);
    context.moveTo(-u4, -t);
    context.lineTo(u4, t);
    context.moveTo(-u4, t);
    context.lineTo(u4, -t);
  }
};

// node_modules/d3-shape/src/symbol/circle.js
var circle_default3 = {
  draw(context, size) {
    const r = sqrt3(size / pi5);
    context.moveTo(r, 0);
    context.arc(0, 0, r, 0, tau6);
  }
};

// node_modules/d3-shape/src/symbol/cross.js
var cross_default2 = {
  draw(context, size) {
    const r = sqrt3(size / 5) / 2;
    context.moveTo(-3 * r, -r);
    context.lineTo(-r, -r);
    context.lineTo(-r, -3 * r);
    context.lineTo(r, -3 * r);
    context.lineTo(r, -r);
    context.lineTo(3 * r, -r);
    context.lineTo(3 * r, r);
    context.lineTo(r, r);
    context.lineTo(r, 3 * r);
    context.lineTo(-r, 3 * r);
    context.lineTo(-r, r);
    context.lineTo(-3 * r, r);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/diamond.js
var tan30 = sqrt3(1 / 3);
var tan30_2 = tan30 * 2;
var diamond_default = {
  draw(context, size) {
    const y3 = sqrt3(size / tan30_2);
    const x3 = y3 * tan30;
    context.moveTo(0, -y3);
    context.lineTo(x3, 0);
    context.lineTo(0, y3);
    context.lineTo(-x3, 0);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/diamond2.js
var diamond2_default = {
  draw(context, size) {
    const r = sqrt3(size) * 0.62625;
    context.moveTo(0, -r);
    context.lineTo(r, 0);
    context.lineTo(0, r);
    context.lineTo(-r, 0);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/plus.js
var plus_default = {
  draw(context, size) {
    const r = sqrt3(size - min3(size / 7, 2)) * 0.87559;
    context.moveTo(-r, 0);
    context.lineTo(r, 0);
    context.moveTo(0, r);
    context.lineTo(0, -r);
  }
};

// node_modules/d3-shape/src/symbol/square.js
var square_default = {
  draw(context, size) {
    const w = sqrt3(size);
    const x3 = -w / 2;
    context.rect(x3, x3, w, w);
  }
};

// node_modules/d3-shape/src/symbol/square2.js
var square2_default = {
  draw(context, size) {
    const r = sqrt3(size) * 0.4431;
    context.moveTo(r, r);
    context.lineTo(r, -r);
    context.lineTo(-r, -r);
    context.lineTo(-r, r);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/star.js
var ka = 0.8908130915292852;
var kr = sin3(pi5 / 10) / sin3(7 * pi5 / 10);
var kx = sin3(tau6 / 10) * kr;
var ky = -cos3(tau6 / 10) * kr;
var star_default = {
  draw(context, size) {
    const r = sqrt3(size * ka);
    const x3 = kx * r;
    const y3 = ky * r;
    context.moveTo(0, -r);
    context.lineTo(x3, y3);
    for (let i = 1; i < 5; ++i) {
      const a2 = tau6 * i / 5;
      const c4 = cos3(a2);
      const s2 = sin3(a2);
      context.lineTo(s2 * r, -c4 * r);
      context.lineTo(c4 * x3 - s2 * y3, s2 * x3 + c4 * y3);
    }
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/triangle.js
var sqrt33 = sqrt3(3);
var triangle_default = {
  draw(context, size) {
    const y3 = -sqrt3(size / (sqrt33 * 3));
    context.moveTo(0, y3 * 2);
    context.lineTo(-sqrt33 * y3, -y3);
    context.lineTo(sqrt33 * y3, -y3);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/triangle2.js
var sqrt34 = sqrt3(3);
var triangle2_default = {
  draw(context, size) {
    const s2 = sqrt3(size) * 0.6824;
    const t = s2 / 2;
    const u4 = s2 * sqrt34 / 2;
    context.moveTo(0, -s2);
    context.lineTo(u4, t);
    context.lineTo(-u4, t);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/wye.js
var c3 = -0.5;
var s = sqrt3(3) / 2;
var k = 1 / sqrt3(12);
var a = (k / 2 + 1) * 3;
var wye_default = {
  draw(context, size) {
    const r = sqrt3(size / a);
    const x06 = r / 2, y06 = r * k;
    const x12 = x06, y12 = r * k + r;
    const x22 = -x12, y22 = y12;
    context.moveTo(x06, y06);
    context.lineTo(x12, y12);
    context.lineTo(x22, y22);
    context.lineTo(c3 * x06 - s * y06, s * x06 + c3 * y06);
    context.lineTo(c3 * x12 - s * y12, s * x12 + c3 * y12);
    context.lineTo(c3 * x22 - s * y22, s * x22 + c3 * y22);
    context.lineTo(c3 * x06 + s * y06, c3 * y06 - s * x06);
    context.lineTo(c3 * x12 + s * y12, c3 * y12 - s * x12);
    context.lineTo(c3 * x22 + s * y22, c3 * y22 - s * x22);
    context.closePath();
  }
};

// node_modules/d3-shape/src/symbol/times.js
var times_default = {
  draw(context, size) {
    const r = sqrt3(size - min3(size / 6, 1.7)) * 0.6189;
    context.moveTo(-r, -r);
    context.lineTo(r, r);
    context.moveTo(-r, r);
    context.lineTo(r, -r);
  }
};

// node_modules/d3-shape/src/symbol.js
var symbolsFill = [
  circle_default3,
  cross_default2,
  diamond_default,
  square_default,
  star_default,
  triangle_default,
  wye_default
];
var symbolsStroke = [
  circle_default3,
  plus_default,
  times_default,
  triangle2_default,
  asterisk_default,
  square2_default,
  diamond2_default
];

// node_modules/d3-shape/src/noop.js
function noop_default2() {
}

// node_modules/d3-shape/src/curve/basis.js
function point2(that, x3, y3) {
  that._context.bezierCurveTo(
    (2 * that._x0 + that._x1) / 3,
    (2 * that._y0 + that._y1) / 3,
    (that._x0 + 2 * that._x1) / 3,
    (that._y0 + 2 * that._y1) / 3,
    (that._x0 + 4 * that._x1 + x3) / 6,
    (that._y0 + 4 * that._y1 + y3) / 6
  );
}
function Basis(context) {
  this._context = context;
}
Basis.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._y0 = this._y1 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 3:
        point2(this, this._x1, this._y1);
      // falls through
      case 2:
        this._context.lineTo(this._x1, this._y1);
        break;
    }
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._line ? this._context.lineTo(x3, y3) : this._context.moveTo(x3, y3);
        break;
      case 1:
        this._point = 2;
        break;
      case 2:
        this._point = 3;
        this._context.lineTo((5 * this._x0 + this._x1) / 6, (5 * this._y0 + this._y1) / 6);
      // falls through
      default:
        point2(this, x3, y3);
        break;
    }
    this._x0 = this._x1, this._x1 = x3;
    this._y0 = this._y1, this._y1 = y3;
  }
};
function basis_default2(context) {
  return new Basis(context);
}

// node_modules/d3-shape/src/curve/basisClosed.js
function BasisClosed(context) {
  this._context = context;
}
BasisClosed.prototype = {
  areaStart: noop_default2,
  areaEnd: noop_default2,
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._x3 = this._x4 = this._y0 = this._y1 = this._y2 = this._y3 = this._y4 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 1: {
        this._context.moveTo(this._x2, this._y2);
        this._context.closePath();
        break;
      }
      case 2: {
        this._context.moveTo((this._x2 + 2 * this._x3) / 3, (this._y2 + 2 * this._y3) / 3);
        this._context.lineTo((this._x3 + 2 * this._x2) / 3, (this._y3 + 2 * this._y2) / 3);
        this._context.closePath();
        break;
      }
      case 3: {
        this.point(this._x2, this._y2);
        this.point(this._x3, this._y3);
        this.point(this._x4, this._y4);
        break;
      }
    }
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._x2 = x3, this._y2 = y3;
        break;
      case 1:
        this._point = 2;
        this._x3 = x3, this._y3 = y3;
        break;
      case 2:
        this._point = 3;
        this._x4 = x3, this._y4 = y3;
        this._context.moveTo((this._x0 + 4 * this._x1 + x3) / 6, (this._y0 + 4 * this._y1 + y3) / 6);
        break;
      default:
        point2(this, x3, y3);
        break;
    }
    this._x0 = this._x1, this._x1 = x3;
    this._y0 = this._y1, this._y1 = y3;
  }
};
function basisClosed_default2(context) {
  return new BasisClosed(context);
}

// node_modules/d3-shape/src/curve/basisOpen.js
function BasisOpen(context) {
  this._context = context;
}
BasisOpen.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._y0 = this._y1 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    if (this._line || this._line !== 0 && this._point === 3) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        break;
      case 1:
        this._point = 2;
        break;
      case 2:
        this._point = 3;
        var x06 = (this._x0 + 4 * this._x1 + x3) / 6, y06 = (this._y0 + 4 * this._y1 + y3) / 6;
        this._line ? this._context.lineTo(x06, y06) : this._context.moveTo(x06, y06);
        break;
      case 3:
        this._point = 4;
      // falls through
      default:
        point2(this, x3, y3);
        break;
    }
    this._x0 = this._x1, this._x1 = x3;
    this._y0 = this._y1, this._y1 = y3;
  }
};
function basisOpen_default(context) {
  return new BasisOpen(context);
}

// node_modules/d3-shape/src/curve/bundle.js
function Bundle(context, beta) {
  this._basis = new Basis(context);
  this._beta = beta;
}
Bundle.prototype = {
  lineStart: function() {
    this._x = [];
    this._y = [];
    this._basis.lineStart();
  },
  lineEnd: function() {
    var x3 = this._x, y3 = this._y, j = x3.length - 1;
    if (j > 0) {
      var x06 = x3[0], y06 = y3[0], dx = x3[j] - x06, dy = y3[j] - y06, i = -1, t;
      while (++i <= j) {
        t = i / j;
        this._basis.point(
          this._beta * x3[i] + (1 - this._beta) * (x06 + t * dx),
          this._beta * y3[i] + (1 - this._beta) * (y06 + t * dy)
        );
      }
    }
    this._x = this._y = null;
    this._basis.lineEnd();
  },
  point: function(x3, y3) {
    this._x.push(+x3);
    this._y.push(+y3);
  }
};
var bundle_default = (function custom12(beta) {
  function bundle(context) {
    return beta === 1 ? new Basis(context) : new Bundle(context, beta);
  }
  bundle.beta = function(beta2) {
    return custom12(+beta2);
  };
  return bundle;
})(0.85);

// node_modules/d3-shape/src/curve/cardinal.js
function point3(that, x3, y3) {
  that._context.bezierCurveTo(
    that._x1 + that._k * (that._x2 - that._x0),
    that._y1 + that._k * (that._y2 - that._y0),
    that._x2 + that._k * (that._x1 - x3),
    that._y2 + that._k * (that._y1 - y3),
    that._x2,
    that._y2
  );
}
function Cardinal(context, tension) {
  this._context = context;
  this._k = (1 - tension) / 6;
}
Cardinal.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._y0 = this._y1 = this._y2 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 2:
        this._context.lineTo(this._x2, this._y2);
        break;
      case 3:
        point3(this, this._x1, this._y1);
        break;
    }
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._line ? this._context.lineTo(x3, y3) : this._context.moveTo(x3, y3);
        break;
      case 1:
        this._point = 2;
        this._x1 = x3, this._y1 = y3;
        break;
      case 2:
        this._point = 3;
      // falls through
      default:
        point3(this, x3, y3);
        break;
    }
    this._x0 = this._x1, this._x1 = this._x2, this._x2 = x3;
    this._y0 = this._y1, this._y1 = this._y2, this._y2 = y3;
  }
};
var cardinal_default = (function custom13(tension) {
  function cardinal(context) {
    return new Cardinal(context, tension);
  }
  cardinal.tension = function(tension2) {
    return custom13(+tension2);
  };
  return cardinal;
})(0);

// node_modules/d3-shape/src/curve/cardinalClosed.js
function CardinalClosed(context, tension) {
  this._context = context;
  this._k = (1 - tension) / 6;
}
CardinalClosed.prototype = {
  areaStart: noop_default2,
  areaEnd: noop_default2,
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._x3 = this._x4 = this._x5 = this._y0 = this._y1 = this._y2 = this._y3 = this._y4 = this._y5 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 1: {
        this._context.moveTo(this._x3, this._y3);
        this._context.closePath();
        break;
      }
      case 2: {
        this._context.lineTo(this._x3, this._y3);
        this._context.closePath();
        break;
      }
      case 3: {
        this.point(this._x3, this._y3);
        this.point(this._x4, this._y4);
        this.point(this._x5, this._y5);
        break;
      }
    }
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._x3 = x3, this._y3 = y3;
        break;
      case 1:
        this._point = 2;
        this._context.moveTo(this._x4 = x3, this._y4 = y3);
        break;
      case 2:
        this._point = 3;
        this._x5 = x3, this._y5 = y3;
        break;
      default:
        point3(this, x3, y3);
        break;
    }
    this._x0 = this._x1, this._x1 = this._x2, this._x2 = x3;
    this._y0 = this._y1, this._y1 = this._y2, this._y2 = y3;
  }
};
var cardinalClosed_default = (function custom14(tension) {
  function cardinal(context) {
    return new CardinalClosed(context, tension);
  }
  cardinal.tension = function(tension2) {
    return custom14(+tension2);
  };
  return cardinal;
})(0);

// node_modules/d3-shape/src/curve/cardinalOpen.js
function CardinalOpen(context, tension) {
  this._context = context;
  this._k = (1 - tension) / 6;
}
CardinalOpen.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._y0 = this._y1 = this._y2 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    if (this._line || this._line !== 0 && this._point === 3) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        break;
      case 1:
        this._point = 2;
        break;
      case 2:
        this._point = 3;
        this._line ? this._context.lineTo(this._x2, this._y2) : this._context.moveTo(this._x2, this._y2);
        break;
      case 3:
        this._point = 4;
      // falls through
      default:
        point3(this, x3, y3);
        break;
    }
    this._x0 = this._x1, this._x1 = this._x2, this._x2 = x3;
    this._y0 = this._y1, this._y1 = this._y2, this._y2 = y3;
  }
};
var cardinalOpen_default = (function custom15(tension) {
  function cardinal(context) {
    return new CardinalOpen(context, tension);
  }
  cardinal.tension = function(tension2) {
    return custom15(+tension2);
  };
  return cardinal;
})(0);

// node_modules/d3-shape/src/curve/catmullRom.js
function point4(that, x3, y3) {
  var x12 = that._x1, y12 = that._y1, x22 = that._x2, y22 = that._y2;
  if (that._l01_a > epsilon8) {
    var a2 = 2 * that._l01_2a + 3 * that._l01_a * that._l12_a + that._l12_2a, n = 3 * that._l01_a * (that._l01_a + that._l12_a);
    x12 = (x12 * a2 - that._x0 * that._l12_2a + that._x2 * that._l01_2a) / n;
    y12 = (y12 * a2 - that._y0 * that._l12_2a + that._y2 * that._l01_2a) / n;
  }
  if (that._l23_a > epsilon8) {
    var b = 2 * that._l23_2a + 3 * that._l23_a * that._l12_a + that._l12_2a, m = 3 * that._l23_a * (that._l23_a + that._l12_a);
    x22 = (x22 * b + that._x1 * that._l23_2a - x3 * that._l12_2a) / m;
    y22 = (y22 * b + that._y1 * that._l23_2a - y3 * that._l12_2a) / m;
  }
  that._context.bezierCurveTo(x12, y12, x22, y22, that._x2, that._y2);
}
function CatmullRom(context, alpha) {
  this._context = context;
  this._alpha = alpha;
}
CatmullRom.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._y0 = this._y1 = this._y2 = NaN;
    this._l01_a = this._l12_a = this._l23_a = this._l01_2a = this._l12_2a = this._l23_2a = this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 2:
        this._context.lineTo(this._x2, this._y2);
        break;
      case 3:
        this.point(this._x2, this._y2);
        break;
    }
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    if (this._point) {
      var x23 = this._x2 - x3, y23 = this._y2 - y3;
      this._l23_a = Math.sqrt(this._l23_2a = Math.pow(x23 * x23 + y23 * y23, this._alpha));
    }
    switch (this._point) {
      case 0:
        this._point = 1;
        this._line ? this._context.lineTo(x3, y3) : this._context.moveTo(x3, y3);
        break;
      case 1:
        this._point = 2;
        break;
      case 2:
        this._point = 3;
      // falls through
      default:
        point4(this, x3, y3);
        break;
    }
    this._l01_a = this._l12_a, this._l12_a = this._l23_a;
    this._l01_2a = this._l12_2a, this._l12_2a = this._l23_2a;
    this._x0 = this._x1, this._x1 = this._x2, this._x2 = x3;
    this._y0 = this._y1, this._y1 = this._y2, this._y2 = y3;
  }
};
var catmullRom_default = (function custom16(alpha) {
  function catmullRom(context) {
    return alpha ? new CatmullRom(context, alpha) : new Cardinal(context, 0);
  }
  catmullRom.alpha = function(alpha2) {
    return custom16(+alpha2);
  };
  return catmullRom;
})(0.5);

// node_modules/d3-shape/src/curve/catmullRomClosed.js
function CatmullRomClosed(context, alpha) {
  this._context = context;
  this._alpha = alpha;
}
CatmullRomClosed.prototype = {
  areaStart: noop_default2,
  areaEnd: noop_default2,
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._x3 = this._x4 = this._x5 = this._y0 = this._y1 = this._y2 = this._y3 = this._y4 = this._y5 = NaN;
    this._l01_a = this._l12_a = this._l23_a = this._l01_2a = this._l12_2a = this._l23_2a = this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 1: {
        this._context.moveTo(this._x3, this._y3);
        this._context.closePath();
        break;
      }
      case 2: {
        this._context.lineTo(this._x3, this._y3);
        this._context.closePath();
        break;
      }
      case 3: {
        this.point(this._x3, this._y3);
        this.point(this._x4, this._y4);
        this.point(this._x5, this._y5);
        break;
      }
    }
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    if (this._point) {
      var x23 = this._x2 - x3, y23 = this._y2 - y3;
      this._l23_a = Math.sqrt(this._l23_2a = Math.pow(x23 * x23 + y23 * y23, this._alpha));
    }
    switch (this._point) {
      case 0:
        this._point = 1;
        this._x3 = x3, this._y3 = y3;
        break;
      case 1:
        this._point = 2;
        this._context.moveTo(this._x4 = x3, this._y4 = y3);
        break;
      case 2:
        this._point = 3;
        this._x5 = x3, this._y5 = y3;
        break;
      default:
        point4(this, x3, y3);
        break;
    }
    this._l01_a = this._l12_a, this._l12_a = this._l23_a;
    this._l01_2a = this._l12_2a, this._l12_2a = this._l23_2a;
    this._x0 = this._x1, this._x1 = this._x2, this._x2 = x3;
    this._y0 = this._y1, this._y1 = this._y2, this._y2 = y3;
  }
};
var catmullRomClosed_default = (function custom17(alpha) {
  function catmullRom(context) {
    return alpha ? new CatmullRomClosed(context, alpha) : new CardinalClosed(context, 0);
  }
  catmullRom.alpha = function(alpha2) {
    return custom17(+alpha2);
  };
  return catmullRom;
})(0.5);

// node_modules/d3-shape/src/curve/catmullRomOpen.js
function CatmullRomOpen(context, alpha) {
  this._context = context;
  this._alpha = alpha;
}
CatmullRomOpen.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._x2 = this._y0 = this._y1 = this._y2 = NaN;
    this._l01_a = this._l12_a = this._l23_a = this._l01_2a = this._l12_2a = this._l23_2a = this._point = 0;
  },
  lineEnd: function() {
    if (this._line || this._line !== 0 && this._point === 3) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    if (this._point) {
      var x23 = this._x2 - x3, y23 = this._y2 - y3;
      this._l23_a = Math.sqrt(this._l23_2a = Math.pow(x23 * x23 + y23 * y23, this._alpha));
    }
    switch (this._point) {
      case 0:
        this._point = 1;
        break;
      case 1:
        this._point = 2;
        break;
      case 2:
        this._point = 3;
        this._line ? this._context.lineTo(this._x2, this._y2) : this._context.moveTo(this._x2, this._y2);
        break;
      case 3:
        this._point = 4;
      // falls through
      default:
        point4(this, x3, y3);
        break;
    }
    this._l01_a = this._l12_a, this._l12_a = this._l23_a;
    this._l01_2a = this._l12_2a, this._l12_2a = this._l23_2a;
    this._x0 = this._x1, this._x1 = this._x2, this._x2 = x3;
    this._y0 = this._y1, this._y1 = this._y2, this._y2 = y3;
  }
};
var catmullRomOpen_default = (function custom18(alpha) {
  function catmullRom(context) {
    return alpha ? new CatmullRomOpen(context, alpha) : new CardinalOpen(context, 0);
  }
  catmullRom.alpha = function(alpha2) {
    return custom18(+alpha2);
  };
  return catmullRom;
})(0.5);

// node_modules/d3-shape/src/curve/linearClosed.js
function LinearClosed(context) {
  this._context = context;
}
LinearClosed.prototype = {
  areaStart: noop_default2,
  areaEnd: noop_default2,
  lineStart: function() {
    this._point = 0;
  },
  lineEnd: function() {
    if (this._point) this._context.closePath();
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    if (this._point) this._context.lineTo(x3, y3);
    else this._point = 1, this._context.moveTo(x3, y3);
  }
};
function linearClosed_default(context) {
  return new LinearClosed(context);
}

// node_modules/d3-shape/src/curve/monotone.js
function sign2(x3) {
  return x3 < 0 ? -1 : 1;
}
function slope3(that, x22, y22) {
  var h0 = that._x1 - that._x0, h1 = x22 - that._x1, s0 = (that._y1 - that._y0) / (h0 || h1 < 0 && -0), s1 = (y22 - that._y1) / (h1 || h0 < 0 && -0), p = (s0 * h1 + s1 * h0) / (h0 + h1);
  return (sign2(s0) + sign2(s1)) * Math.min(Math.abs(s0), Math.abs(s1), 0.5 * Math.abs(p)) || 0;
}
function slope2(that, t) {
  var h = that._x1 - that._x0;
  return h ? (3 * (that._y1 - that._y0) / h - t) / 2 : t;
}
function point5(that, t03, t13) {
  var x06 = that._x0, y06 = that._y0, x12 = that._x1, y12 = that._y1, dx = (x12 - x06) / 3;
  that._context.bezierCurveTo(x06 + dx, y06 + dx * t03, x12 - dx, y12 - dx * t13, x12, y12);
}
function MonotoneX(context) {
  this._context = context;
}
MonotoneX.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x0 = this._x1 = this._y0 = this._y1 = this._t0 = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    switch (this._point) {
      case 2:
        this._context.lineTo(this._x1, this._y1);
        break;
      case 3:
        point5(this, this._t0, slope2(this, this._t0));
        break;
    }
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    var t13 = NaN;
    x3 = +x3, y3 = +y3;
    if (x3 === this._x1 && y3 === this._y1) return;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._line ? this._context.lineTo(x3, y3) : this._context.moveTo(x3, y3);
        break;
      case 1:
        this._point = 2;
        break;
      case 2:
        this._point = 3;
        point5(this, slope2(this, t13 = slope3(this, x3, y3)), t13);
        break;
      default:
        point5(this, this._t0, t13 = slope3(this, x3, y3));
        break;
    }
    this._x0 = this._x1, this._x1 = x3;
    this._y0 = this._y1, this._y1 = y3;
    this._t0 = t13;
  }
};
function MonotoneY(context) {
  this._context = new ReflectContext(context);
}
(MonotoneY.prototype = Object.create(MonotoneX.prototype)).point = function(x3, y3) {
  MonotoneX.prototype.point.call(this, y3, x3);
};
function ReflectContext(context) {
  this._context = context;
}
ReflectContext.prototype = {
  moveTo: function(x3, y3) {
    this._context.moveTo(y3, x3);
  },
  closePath: function() {
    this._context.closePath();
  },
  lineTo: function(x3, y3) {
    this._context.lineTo(y3, x3);
  },
  bezierCurveTo: function(x12, y12, x22, y22, x3, y3) {
    this._context.bezierCurveTo(y12, x12, y22, x22, y3, x3);
  }
};
function monotoneX(context) {
  return new MonotoneX(context);
}
function monotoneY(context) {
  return new MonotoneY(context);
}

// node_modules/d3-shape/src/curve/natural.js
function Natural(context) {
  this._context = context;
}
Natural.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x = [];
    this._y = [];
  },
  lineEnd: function() {
    var x3 = this._x, y3 = this._y, n = x3.length;
    if (n) {
      this._line ? this._context.lineTo(x3[0], y3[0]) : this._context.moveTo(x3[0], y3[0]);
      if (n === 2) {
        this._context.lineTo(x3[1], y3[1]);
      } else {
        var px = controlPoints(x3), py = controlPoints(y3);
        for (var i0 = 0, i1 = 1; i1 < n; ++i0, ++i1) {
          this._context.bezierCurveTo(px[0][i0], py[0][i0], px[1][i0], py[1][i0], x3[i1], y3[i1]);
        }
      }
    }
    if (this._line || this._line !== 0 && n === 1) this._context.closePath();
    this._line = 1 - this._line;
    this._x = this._y = null;
  },
  point: function(x3, y3) {
    this._x.push(+x3);
    this._y.push(+y3);
  }
};
function controlPoints(x3) {
  var i, n = x3.length - 1, m, a2 = new Array(n), b = new Array(n), r = new Array(n);
  a2[0] = 0, b[0] = 2, r[0] = x3[0] + 2 * x3[1];
  for (i = 1; i < n - 1; ++i) a2[i] = 1, b[i] = 4, r[i] = 4 * x3[i] + 2 * x3[i + 1];
  a2[n - 1] = 2, b[n - 1] = 7, r[n - 1] = 8 * x3[n - 1] + x3[n];
  for (i = 1; i < n; ++i) m = a2[i] / b[i - 1], b[i] -= m, r[i] -= m * r[i - 1];
  a2[n - 1] = r[n - 1] / b[n - 1];
  for (i = n - 2; i >= 0; --i) a2[i] = (r[i] - a2[i + 1]) / b[i];
  b[n - 1] = (x3[n] + a2[n - 1]) / 2;
  for (i = 0; i < n - 1; ++i) b[i] = 2 * x3[i + 1] - a2[i + 1];
  return [a2, b];
}
function natural_default(context) {
  return new Natural(context);
}

// node_modules/d3-shape/src/curve/step.js
function Step(context, t) {
  this._context = context;
  this._t = t;
}
Step.prototype = {
  areaStart: function() {
    this._line = 0;
  },
  areaEnd: function() {
    this._line = NaN;
  },
  lineStart: function() {
    this._x = this._y = NaN;
    this._point = 0;
  },
  lineEnd: function() {
    if (0 < this._t && this._t < 1 && this._point === 2) this._context.lineTo(this._x, this._y);
    if (this._line || this._line !== 0 && this._point === 1) this._context.closePath();
    if (this._line >= 0) this._t = 1 - this._t, this._line = 1 - this._line;
  },
  point: function(x3, y3) {
    x3 = +x3, y3 = +y3;
    switch (this._point) {
      case 0:
        this._point = 1;
        this._line ? this._context.lineTo(x3, y3) : this._context.moveTo(x3, y3);
        break;
      case 1:
        this._point = 2;
      // falls through
      default: {
        if (this._t <= 0) {
          this._context.lineTo(this._x, y3);
          this._context.lineTo(x3, y3);
        } else {
          var x12 = this._x * (1 - this._t) + x3 * this._t;
          this._context.lineTo(x12, this._y);
          this._context.lineTo(x12, y3);
        }
        break;
      }
    }
    this._x = x3, this._y = y3;
  }
};
function step_default(context) {
  return new Step(context, 0.5);
}
function stepBefore(context) {
  return new Step(context, 0);
}
function stepAfter(context) {
  return new Step(context, 1);
}

// node_modules/d3-zoom/src/transform.js
function Transform(k2, x3, y3) {
  this.k = k2;
  this.x = x3;
  this.y = y3;
}
Transform.prototype = {
  constructor: Transform,
  scale: function(k2) {
    return k2 === 1 ? this : new Transform(this.k * k2, this.x, this.y);
  },
  translate: function(x3, y3) {
    return x3 === 0 & y3 === 0 ? this : new Transform(this.k, this.x + this.k * x3, this.y + this.k * y3);
  },
  apply: function(point6) {
    return [point6[0] * this.k + this.x, point6[1] * this.k + this.y];
  },
  applyX: function(x3) {
    return x3 * this.k + this.x;
  },
  applyY: function(y3) {
    return y3 * this.k + this.y;
  },
  invert: function(location) {
    return [(location[0] - this.x) / this.k, (location[1] - this.y) / this.k];
  },
  invertX: function(x3) {
    return (x3 - this.x) / this.k;
  },
  invertY: function(y3) {
    return (y3 - this.y) / this.k;
  },
  rescaleX: function(x3) {
    return x3.copy().domain(x3.range().map(this.invertX, this).map(x3.invert, x3));
  },
  rescaleY: function(y3) {
    return y3.copy().domain(y3.range().map(this.invertY, this).map(y3.invert, y3));
  },
  toString: function() {
    return "translate(" + this.x + "," + this.y + ") scale(" + this.k + ")";
  }
};
var identity5 = new Transform(1, 0, 0);
transform.prototype = Transform.prototype;
function transform(node) {
  while (!node.__zoom) if (!(node = node.parentNode)) return identity5;
  return node.__zoom;
}

// node_modules/@observablehq/plot/src/defined.js
function defined(x3) {
  return x3 != null && !Number.isNaN(x3);
}
function ascendingDefined2(a2, b) {
  return +defined(b) - +defined(a2) || ascending(a2, b);
}
function descendingDefined(a2, b) {
  return +defined(b) - +defined(a2) || descending(a2, b);
}
function nonempty(x3) {
  return x3 != null && `${x3}` !== "";
}
function finite2(x3) {
  return isFinite(x3) ? x3 : NaN;
}
function positive(x3) {
  return x3 > 0 && isFinite(x3) ? x3 : NaN;
}
function negative(x3) {
  return x3 < 0 && isFinite(x3) ? x3 : NaN;
}

// node_modules/isoformat/src/format.js
function format2(date2, fallback) {
  if (!(date2 instanceof Date)) date2 = /* @__PURE__ */ new Date(+date2);
  if (isNaN(date2)) return typeof fallback === "function" ? fallback(date2) : fallback;
  const hours = date2.getUTCHours();
  const minutes = date2.getUTCMinutes();
  const seconds2 = date2.getUTCSeconds();
  const milliseconds2 = date2.getUTCMilliseconds();
  return `${formatYear3(date2.getUTCFullYear(), 4)}-${pad3(date2.getUTCMonth() + 1, 2)}-${pad3(date2.getUTCDate(), 2)}${hours || minutes || seconds2 || milliseconds2 ? `T${pad3(hours, 2)}:${pad3(minutes, 2)}${seconds2 || milliseconds2 ? `:${pad3(seconds2, 2)}${milliseconds2 ? `.${pad3(milliseconds2, 3)}` : ``}` : ``}Z` : ``}`;
}
function formatYear3(year) {
  return year < 0 ? `-${pad3(-year, 6)}` : year > 9999 ? `+${pad3(year, 6)}` : pad3(year, 4);
}
function pad3(value, width) {
  return `${value}`.padStart(width, "0");
}

// node_modules/isoformat/src/parse.js
var re2 = /^(?:[-+]\d{2})?\d{4}(?:-\d{2}(?:-\d{2})?)?(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{3})?)?(?:Z|[-+]\d{2}:?\d{2})?)?$/;
function parse(string2, fallback) {
  if (!re2.test(string2 += "")) return typeof fallback === "function" ? fallback(string2) : fallback;
  return new Date(string2);
}

// node_modules/@observablehq/plot/src/order.js
function orderof(values2) {
  if (values2 == null) return;
  const first2 = values2[0];
  const last = values2[values2.length - 1];
  return descending(first2, last);
}

// node_modules/@observablehq/plot/src/time.js
var durationSecond2 = 1e3;
var durationMinute2 = durationSecond2 * 60;
var durationHour2 = durationMinute2 * 60;
var durationDay2 = durationHour2 * 24;
var durationWeek2 = durationDay2 * 7;
var durationMonth2 = durationDay2 * 30;
var durationYear2 = durationDay2 * 365;
var tickIntervals = [
  ["millisecond", 1],
  ["2 milliseconds", 2],
  ["5 milliseconds", 5],
  ["10 milliseconds", 10],
  ["20 milliseconds", 20],
  ["50 milliseconds", 50],
  ["100 milliseconds", 100],
  ["200 milliseconds", 200],
  ["500 milliseconds", 500],
  ["second", durationSecond2],
  ["5 seconds", 5 * durationSecond2],
  ["15 seconds", 15 * durationSecond2],
  ["30 seconds", 30 * durationSecond2],
  ["minute", durationMinute2],
  ["5 minutes", 5 * durationMinute2],
  ["15 minutes", 15 * durationMinute2],
  ["30 minutes", 30 * durationMinute2],
  ["hour", durationHour2],
  ["3 hours", 3 * durationHour2],
  ["6 hours", 6 * durationHour2],
  ["12 hours", 12 * durationHour2],
  ["day", durationDay2],
  ["2 days", 2 * durationDay2],
  ["week", durationWeek2],
  ["2 weeks", 2 * durationWeek2],
  // https://github.com/d3/d3-time/issues/46
  ["month", durationMonth2],
  ["3 months", 3 * durationMonth2],
  ["6 months", 6 * durationMonth2],
  // https://github.com/d3/d3-time/issues/46
  ["year", durationYear2],
  ["2 years", 2 * durationYear2],
  ["5 years", 5 * durationYear2],
  ["10 years", 10 * durationYear2],
  ["20 years", 20 * durationYear2],
  ["50 years", 50 * durationYear2],
  ["100 years", 100 * durationYear2]
  // TODO generalize to longer time scales
];
var durations = /* @__PURE__ */ new Map([
  ["second", durationSecond2],
  ["minute", durationMinute2],
  ["hour", durationHour2],
  ["day", durationDay2],
  ["monday", durationWeek2],
  ["tuesday", durationWeek2],
  ["wednesday", durationWeek2],
  ["thursday", durationWeek2],
  ["friday", durationWeek2],
  ["saturday", durationWeek2],
  ["sunday", durationWeek2],
  ["week", durationWeek2],
  ["month", durationMonth2],
  ["year", durationYear2]
]);
var timeIntervals = /* @__PURE__ */ new Map([
  ["second", second],
  ["minute", timeMinute],
  ["hour", timeHour],
  ["day", timeDay],
  // https://github.com/d3/d3-time/issues/62
  ["monday", timeMonday],
  ["tuesday", timeTuesday],
  ["wednesday", timeWednesday],
  ["thursday", timeThursday],
  ["friday", timeFriday],
  ["saturday", timeSaturday],
  ["sunday", timeSunday],
  ["week", timeSunday],
  ["month", timeMonth],
  ["year", timeYear]
]);
var utcIntervals = /* @__PURE__ */ new Map([
  ["second", second],
  ["minute", utcMinute],
  ["hour", utcHour],
  ["day", unixDay],
  ["monday", utcMonday],
  ["tuesday", utcTuesday],
  ["wednesday", utcWednesday],
  ["thursday", utcThursday],
  ["friday", utcFriday],
  ["saturday", utcSaturday],
  ["sunday", utcSunday],
  ["week", utcSunday],
  ["month", utcMonth],
  ["year", utcYear]
]);
var intervalDuration = Symbol("intervalDuration");
var intervalType = Symbol("intervalType");
for (const [name, interval2] of timeIntervals) {
  interval2[intervalDuration] = durations.get(name);
  interval2[intervalType] = "time";
}
for (const [name, interval2] of utcIntervals) {
  interval2[intervalDuration] = durations.get(name);
  interval2[intervalType] = "utc";
}
var utcFormatIntervals = [
  ["year", utcYear, "utc"],
  ["month", utcMonth, "utc"],
  ["day", unixDay, "utc", 6 * durationMonth2],
  ["hour", utcHour, "utc", 3 * durationDay2],
  ["minute", utcMinute, "utc", 6 * durationHour2],
  ["second", second, "utc", 30 * durationMinute2]
];
var timeFormatIntervals = [
  ["year", timeYear, "time"],
  ["month", timeMonth, "time"],
  ["day", timeDay, "time", 6 * durationMonth2],
  ["hour", timeHour, "time", 3 * durationDay2],
  ["minute", timeMinute, "time", 6 * durationHour2],
  ["second", second, "time", 30 * durationMinute2]
];
var formatIntervals = [
  utcFormatIntervals[0],
  timeFormatIntervals[0],
  utcFormatIntervals[1],
  timeFormatIntervals[1],
  utcFormatIntervals[2],
  timeFormatIntervals[2],
  // Below day, local time typically has an hourly offset from UTC and hence the
  // two are aligned and indistinguishable; therefore, we only consider UTC, and
  // we don’t consider these if the domain only has a single value.
  ...utcFormatIntervals.slice(3)
];
function parseTimeInterval(input) {
  let name = `${input}`.toLowerCase();
  if (name.endsWith("s")) name = name.slice(0, -1);
  let period2 = 1;
  const match = /^(?:(\d+)\s+)/.exec(name);
  if (match) {
    name = name.slice(match[0].length);
    period2 = +match[1];
  }
  switch (name) {
    case "quarter":
      name = "month";
      period2 *= 3;
      break;
    case "half":
      name = "month";
      period2 *= 6;
      break;
  }
  let interval2 = utcIntervals.get(name);
  if (!interval2) throw new Error(`unknown interval: ${input}`);
  if (period2 > 1 && !interval2.every) throw new Error(`non-periodic interval: ${name}`);
  return [name, period2];
}
function timeInterval2(input) {
  return asInterval(parseTimeInterval(input), "time");
}
function utcInterval(input) {
  return asInterval(parseTimeInterval(input), "utc");
}
function asInterval([name, period2], type2) {
  let interval2 = (type2 === "time" ? timeIntervals : utcIntervals).get(name);
  if (period2 > 1) {
    interval2 = interval2.every(period2);
    interval2[intervalDuration] = durations.get(name) * period2;
    interval2[intervalType] = type2;
  }
  return interval2;
}
function generalizeTimeInterval(interval2, n) {
  if (!(n > 1)) return;
  const duration = interval2[intervalDuration];
  if (!tickIntervals.some(([, d]) => d === duration)) return;
  if (duration % durationDay2 === 0 && durationDay2 < duration && duration < durationMonth2) return;
  const [i] = tickIntervals[bisector(([, step]) => Math.log(step)).center(tickIntervals, Math.log(duration * n))];
  return (interval2[intervalType] === "time" ? timeInterval2 : utcInterval)(i);
}
function formatTimeInterval(name, type2, anchor) {
  const format3 = type2 === "time" ? timeFormat : utcFormat;
  if (anchor == null) {
    return format3(
      name === "year" ? "%Y" : name === "month" ? "%Y-%m" : name === "day" ? "%Y-%m-%d" : name === "hour" || name === "minute" ? "%Y-%m-%dT%H:%M" : name === "second" ? "%Y-%m-%dT%H:%M:%S" : "%Y-%m-%dT%H:%M:%S.%L"
    );
  }
  const template2 = getTimeTemplate(anchor);
  switch (name) {
    case "millisecond":
      return formatConditional(format3(".%L"), format3(":%M:%S"), template2);
    case "second":
      return formatConditional(format3(":%S"), format3("%-I:%M"), template2);
    case "minute":
      return formatConditional(format3("%-I:%M"), format3("%p"), template2);
    case "hour":
      return formatConditional(format3("%-I %p"), format3("%b %-d"), template2);
    case "day":
      return formatConditional(format3("%-d"), format3("%b"), template2);
    case "month":
      return formatConditional(format3("%b"), format3("%Y"), template2);
    case "year":
      return format3("%Y");
  }
  throw new Error("unable to format time ticks");
}
function getTimeTemplate(anchor) {
  return anchor === "left" || anchor === "right" ? (f1, f2) => `
${f1}
${f2}` : anchor === "top" ? (f1, f2) => `${f2}
${f1}` : (f1, f2) => `${f1}
${f2}`;
}
function getFormatIntervals(type2) {
  return type2 === "time" ? timeFormatIntervals : type2 === "utc" ? utcFormatIntervals : formatIntervals;
}
function inferTimeFormat(type2, dates, anchor) {
  const step = max(pairs(dates, (a2, b) => Math.abs(b - a2)));
  if (step < 1e3) return formatTimeInterval("millisecond", "utc", anchor);
  for (const [name, interval2, intervalType2, maxStep] of getFormatIntervals(type2)) {
    if (step > maxStep) break;
    if (name === "hour" && !step) break;
    if (dates.every((d) => interval2.floor(d) >= d)) return formatTimeInterval(name, intervalType2, anchor);
  }
}
function formatConditional(format1, format22, template2) {
  return (x3, i, X3) => {
    const f1 = format1(x3, i);
    const f2 = format22(x3, i);
    const j = i - orderof(X3);
    return i !== j && X3[j] !== void 0 && f2 === format22(X3[j], j) ? f1 : template2(f1, f2);
  };
}

// node_modules/@observablehq/plot/src/options.js
var TypedArray = Object.getPrototypeOf(Uint8Array);
var objectToString = Object.prototype.toString;
function isArray(value) {
  return value instanceof Array || value instanceof TypedArray;
}
function isNumberArray2(value) {
  return value instanceof TypedArray && !isBigIntArray(value);
}
function isNumberType(type2) {
  return (type2 == null ? void 0 : type2.prototype) instanceof TypedArray && !isBigIntType(type2);
}
function isBigIntArray(value) {
  return value instanceof BigInt64Array || value instanceof BigUint64Array;
}
function isBigIntType(type2) {
  return type2 === BigInt64Array || type2 === BigUint64Array;
}
var reindex = Symbol("reindex");
function valueof(data, value, type2) {
  const valueType = typeof value;
  return valueType === "string" ? isArrowTable(data) ? maybeTypedArrowify(data.getChild(value), type2) : maybeTypedMap(data, field(value), type2) : valueType === "function" ? maybeTypedMap(data, value, type2) : valueType === "number" || value instanceof Date || valueType === "boolean" ? map4(data, constant2(value), type2) : typeof (value == null ? void 0 : value.transform) === "function" ? maybeTypedArrayify(value.transform(data), type2) : maybeTake(maybeTypedArrayify(value, type2), data == null ? void 0 : data[reindex]);
}
function maybeTake(values2, index2) {
  return values2 != null && index2 ? take(values2, index2) : values2;
}
function maybeTypedMap(data, f, type2) {
  return map4(data, isNumberType(type2) ? (d, i) => coerceNumber(f(d, i)) : f, type2);
}
function maybeTypedArrayify(data, type2) {
  return type2 === void 0 ? arrayify2(data) : isArrowVector(data) ? maybeTypedArrowify(data, type2) : data instanceof type2 ? data : type2.from(data, isNumberType(type2) && !isNumberArray2(data) ? coerceNumber : void 0);
}
function maybeTypedArrowify(vector2, type2) {
  return vector2 == null ? vector2 : (type2 === void 0 || type2 === Array) && isArrowDateType(vector2.type) ? coerceDates(vectorToArray(vector2)) : maybeTypedArrayify(vectorToArray(vector2), type2);
}
function vectorToArray(vector2) {
  return vector2.nullCount ? vector2.toJSON() : vector2.toArray();
}
var singleton = [null];
var field = (name) => (d) => {
  var _a;
  const v2 = d[name];
  return v2 === void 0 && d.type === "Feature" ? (_a = d.properties) == null ? void 0 : _a[name] : v2;
};
var indexOf = { transform: range2 };
var identity6 = { transform: (d) => d };
var one2 = () => 1;
var yes = () => true;
var string = (x3) => x3 == null ? x3 : `${x3}`;
var number5 = (x3) => x3 == null ? x3 : +x3;
var first = (x3) => x3 ? x3[0] : void 0;
var second2 = (x3) => x3 ? x3[1] : void 0;
var third = (x3) => x3 ? x3[2] : void 0;
var constant2 = (x3) => () => x3;
function percentile(reduce2) {
  const p = +`${reduce2}`.slice(1) / 100;
  return (I, f) => quantile(I, p, f);
}
function coerceNumbers(values2) {
  return isNumberArray2(values2) ? values2 : map4(values2, coerceNumber, Float64Array);
}
function coerceNumber(x3) {
  return x3 == null ? NaN : Number(x3);
}
function coerceDates(values2) {
  return map4(values2, coerceDate);
}
function coerceDate(x3) {
  return x3 instanceof Date && !isNaN(x3) ? x3 : typeof x3 === "string" ? parse(x3) : x3 == null || isNaN(x3 = Number(x3)) ? void 0 : new Date(x3);
}
function maybeColorChannel(value, defaultValue) {
  if (value === void 0) value = defaultValue;
  return value === null ? [void 0, "none"] : isColor(value) ? [void 0, value] : [value, void 0];
}
function maybeNumberChannel(value, defaultValue) {
  if (value === void 0) value = defaultValue;
  return value === null || typeof value === "number" ? [void 0, value] : [value, void 0];
}
function maybeKeyword(input, name, allowed) {
  if (input != null) return keyword(input, name, allowed);
}
function keyword(input, name, allowed) {
  const i = `${input}`.toLowerCase();
  if (!allowed.includes(i)) throw new Error(`invalid ${name}: ${input}`);
  return i;
}
function dataify(data) {
  return isArrowTable(data) ? data : arrayify2(data);
}
function arrayify2(values2) {
  if (values2 == null || isArray(values2)) return values2;
  if (isArrowVector(values2)) return maybeTypedArrowify(values2);
  if (isGeoJSON(values2)) {
    switch (values2.type) {
      case "FeatureCollection":
        return values2.features;
      case "GeometryCollection":
        return values2.geometries;
      default:
        return [values2];
    }
  }
  return Array.from(values2);
}
function isGeoJSON(x3) {
  switch (x3 == null ? void 0 : x3.type) {
    case "FeatureCollection":
    case "GeometryCollection":
    case "Feature":
    case "LineString":
    case "MultiLineString":
    case "MultiPoint":
    case "MultiPolygon":
    case "Point":
    case "Polygon":
    case "Sphere":
      return true;
    default:
      return false;
  }
}
function map4(values2, f, type2 = Array) {
  return values2 == null ? values2 : values2 instanceof type2 ? values2.map(f) : type2.from(values2, f);
}
function slice5(values2, type2 = Array) {
  return values2 instanceof type2 ? values2.slice() : type2.from(values2);
}
function hasX({ x: x3, x1: x12, x2: x22 }) {
  return x3 !== void 0 || x12 !== void 0 || x22 !== void 0;
}
function hasY({ y: y3, y1: y12, y2: y22 }) {
  return y3 !== void 0 || y12 !== void 0 || y22 !== void 0;
}
function hasXY(options) {
  return hasX(options) || hasY(options) || options.interval !== void 0;
}
function isObject(option) {
  return (option == null ? void 0 : option.toString) === objectToString;
}
function isScaleOptions(option) {
  return isObject(option) && (option.type !== void 0 || option.domain !== void 0);
}
function isOptions(option) {
  return isObject(option) && typeof option.transform !== "function";
}
function isDomainSort(sort3) {
  return isOptions(sort3) && sort3.value === void 0 && sort3.channel === void 0;
}
function maybeZero(x3, x12, x22, x32 = identity6) {
  if (x12 === void 0 && x22 === void 0) {
    x12 = 0, x22 = x3 === void 0 ? x32 : x3;
  } else if (x12 === void 0) {
    x12 = x3 === void 0 ? 0 : x3;
  } else if (x22 === void 0) {
    x22 = x3 === void 0 ? 0 : x3;
  }
  return [x12, x22];
}
function maybeTuple(x3, y3) {
  return x3 === void 0 && y3 === void 0 ? [first, second2] : [x3, y3];
}
function maybeZ({ z, fill, stroke } = {}) {
  if (z === void 0) [z] = maybeColorChannel(fill);
  if (z === void 0) [z] = maybeColorChannel(stroke);
  return z;
}
function lengthof(data) {
  return isArray(data) ? data.length : data == null ? void 0 : data.numRows;
}
function range2(data) {
  const n = lengthof(data);
  const r = new Uint32Array(n);
  for (let i = 0; i < n; ++i) r[i] = i;
  return r;
}
function take(values2, index2) {
  return isArray(values2) ? map4(index2, (i) => values2[i], values2.constructor) : map4(index2, (i) => values2.at(i));
}
function taker(f) {
  return f.length === 1 ? (index2, values2) => f(take(values2, index2)) : f;
}
function subarray(I, i, j) {
  return I.subarray ? I.subarray(i, j) : I.slice(i, j);
}
function keyof2(value) {
  return value !== null && typeof value === "object" ? value.valueOf() : value;
}
function maybeInput(key, options) {
  if (options[key] !== void 0) return options[key];
  switch (key) {
    case "x1":
    case "x2":
      key = "x";
      break;
    case "y1":
    case "y2":
      key = "y";
      break;
  }
  return options[key];
}
function column(source) {
  let value;
  return [
    {
      transform: () => value,
      label: labelof(source)
    },
    (v2) => value = v2
  ];
}
function maybeColumn(source) {
  return source == null ? [source] : column(source);
}
function labelof(value, defaultValue) {
  return typeof value === "string" ? value : value && value.label !== void 0 ? value.label : defaultValue;
}
function mid(x12, x22) {
  return {
    transform(data) {
      const X13 = x12.transform(data);
      const X23 = x22.transform(data);
      return isTemporal(X13) || isTemporal(X23) ? map4(X13, (_, i) => new Date((+X13[i] + +X23[i]) / 2)) : map4(X13, (_, i) => (+X13[i] + +X23[i]) / 2, Float64Array);
    },
    label: x12.label
  };
}
function maybeApplyInterval(V, scale3) {
  const t = maybeIntervalTransform(scale3 == null ? void 0 : scale3.interval, scale3 == null ? void 0 : scale3.type);
  return t ? map4(V, t) : V;
}
function maybeIntervalTransform(interval2, type2) {
  const i = maybeInterval(interval2, type2);
  return i && ((v2) => defined(v2) ? i.floor(v2) : v2);
}
function maybeInterval(interval2, type2) {
  if (interval2 == null) return;
  if (typeof interval2 === "number") return numberInterval(interval2);
  if (typeof interval2 === "string") return (type2 === "time" ? timeInterval2 : utcInterval)(interval2);
  if (typeof interval2.floor !== "function") throw new Error("invalid interval; missing floor method");
  if (typeof interval2.offset !== "function") throw new Error("invalid interval; missing offset method");
  return interval2;
}
function numberInterval(interval2) {
  interval2 = +interval2;
  if (0 < interval2 && interval2 < 1 && Number.isInteger(1 / interval2)) interval2 = -1 / interval2;
  const n = Math.abs(interval2);
  return interval2 < 0 ? {
    floor: (d) => Math.floor(d * n) / n,
    offset: (d, s2 = 1) => (d * n + Math.floor(s2)) / n,
    range: (lo, hi) => range(Math.ceil(lo * n), hi * n).map((x3) => x3 / n)
  } : {
    floor: (d) => Math.floor(d / n) * n,
    offset: (d, s2 = 1) => d + n * Math.floor(s2),
    range: (lo, hi) => range(Math.ceil(lo / n), hi / n).map((x3) => x3 * n)
  };
}
function maybeRangeInterval(interval2, type2) {
  interval2 = maybeInterval(interval2, type2);
  if (interval2 && typeof interval2.range !== "function") throw new Error("invalid interval: missing range method");
  return interval2;
}
function maybeNiceInterval(interval2, type2) {
  interval2 = maybeRangeInterval(interval2, type2);
  if (interval2 && typeof interval2.ceil !== "function") throw new Error("invalid interval: missing ceil method");
  return interval2;
}
function isTimeInterval(t) {
  return isInterval(t) && typeof (t == null ? void 0 : t.floor) === "function" && t.floor() instanceof Date;
}
function isInterval(t) {
  return typeof (t == null ? void 0 : t.range) === "function";
}
function maybeValue(value) {
  return value === void 0 || isOptions(value) ? value : { value };
}
function numberChannel(source) {
  return source == null ? null : {
    transform: (data) => valueof(data, source, Float64Array),
    label: labelof(source)
  };
}
function isTuples(data) {
  if (!isIterable(data)) return false;
  for (const d of data) {
    if (d == null) continue;
    return typeof d === "object" && "0" in d && "1" in d;
  }
}
function isIterable(value) {
  return value && typeof value[Symbol.iterator] === "function";
}
function isTextual(values2) {
  for (const value of values2) {
    if (value == null) continue;
    return typeof value !== "object" || value instanceof Date;
  }
}
function isOrdinal(values2) {
  for (const value of values2) {
    if (value == null) continue;
    const type2 = typeof value;
    return type2 === "string" || type2 === "boolean";
  }
}
function isTemporal(values2) {
  for (const value of values2) {
    if (value == null) continue;
    return value instanceof Date;
  }
}
function isTemporalString(values2) {
  for (const value of values2) {
    if (value == null) continue;
    return typeof value === "string" && isNaN(value) && parse(value);
  }
}
function isNumericString(values2) {
  for (const value of values2) {
    if (value == null) continue;
    if (typeof value !== "string") return false;
    if (!value.trim()) continue;
    return !isNaN(value);
  }
}
function isNumeric(values2) {
  for (const value of values2) {
    if (value == null) continue;
    return typeof value === "number";
  }
}
function isEvery(values2, is) {
  let every2;
  for (const value of values2) {
    if (value == null) continue;
    if (!is(value)) return false;
    every2 = true;
  }
  return every2;
}
var namedColors = new Set("none,currentcolor,transparent,aliceblue,antiquewhite,aqua,aquamarine,azure,beige,bisque,black,blanchedalmond,blue,blueviolet,brown,burlywood,cadetblue,chartreuse,chocolate,coral,cornflowerblue,cornsilk,crimson,cyan,darkblue,darkcyan,darkgoldenrod,darkgray,darkgreen,darkgrey,darkkhaki,darkmagenta,darkolivegreen,darkorange,darkorchid,darkred,darksalmon,darkseagreen,darkslateblue,darkslategray,darkslategrey,darkturquoise,darkviolet,deeppink,deepskyblue,dimgray,dimgrey,dodgerblue,firebrick,floralwhite,forestgreen,fuchsia,gainsboro,ghostwhite,gold,goldenrod,gray,green,greenyellow,grey,honeydew,hotpink,indianred,indigo,ivory,khaki,lavender,lavenderblush,lawngreen,lemonchiffon,lightblue,lightcoral,lightcyan,lightgoldenrodyellow,lightgray,lightgreen,lightgrey,lightpink,lightsalmon,lightseagreen,lightskyblue,lightslategray,lightslategrey,lightsteelblue,lightyellow,lime,limegreen,linen,magenta,maroon,mediumaquamarine,mediumblue,mediumorchid,mediumpurple,mediumseagreen,mediumslateblue,mediumspringgreen,mediumturquoise,mediumvioletred,midnightblue,mintcream,mistyrose,moccasin,navajowhite,navy,oldlace,olive,olivedrab,orange,orangered,orchid,palegoldenrod,palegreen,paleturquoise,palevioletred,papayawhip,peachpuff,peru,pink,plum,powderblue,purple,rebeccapurple,red,rosybrown,royalblue,saddlebrown,salmon,sandybrown,seagreen,seashell,sienna,silver,skyblue,slateblue,slategray,slategrey,snow,springgreen,steelblue,tan,teal,thistle,tomato,turquoise,violet,wheat,white,whitesmoke,yellow".split(","));
function isColor(value) {
  if (typeof value !== "string") return false;
  value = value.toLowerCase().trim();
  return /^#[0-9a-f]{3,8}$/.test(value) || // hex rgb, rgba, rrggbb, rrggbbaa
  /^(?:url|var|rgb|rgba|hsl|hsla|hwb|lab|lch|oklab|oklch|color|color-mix)\(.*\)$/.test(value) || // <funciri>, CSS variable, color, etc.
  namedColors.has(value);
}
function isOpacity(value) {
  return typeof value === "number" && (0 <= value && value <= 1 || isNaN(value));
}
function isNoneish(value) {
  return value == null || isNone(value);
}
function isNone(value) {
  return /^\s*none\s*$/i.test(value);
}
function isRound(value) {
  return /^\s*round\s*$/i.test(value);
}
function maybeAnchor(value, name) {
  return maybeKeyword(value, name, [
    "middle",
    "top-left",
    "top",
    "top-right",
    "right",
    "bottom-right",
    "bottom",
    "bottom-left",
    "left"
  ]);
}
function maybeFrameAnchor(value = "middle") {
  return maybeAnchor(value, "frameAnchor");
}
function inherit2(options = {}, ...rest) {
  let o = options;
  for (const defaults22 of rest) {
    for (const key in defaults22) {
      if (o[key] === void 0) {
        const value = defaults22[key];
        if (o === options) o = { ...o, [key]: value };
        else o[key] = value;
      }
    }
  }
  return o;
}
function named2(things) {
  console.warn("named iterables are deprecated; please use an object instead");
  const names = /* @__PURE__ */ new Set();
  return Object.fromEntries(
    Array.from(things, (thing) => {
      const { name } = thing;
      if (name == null) throw new Error("missing name");
      const key = `${name}`;
      if (key === "__proto__") throw new Error(`illegal name: ${key}`);
      if (names.has(key)) throw new Error(`duplicate name: ${key}`);
      names.add(key);
      return [name, thing];
    })
  );
}
function maybeNamed(things) {
  return isIterable(things) ? named2(things) : things;
}
function maybeClip(clip) {
  if (clip === true) clip = "frame";
  else if (clip === false) clip = null;
  else if (!isGeoJSON(clip) && clip != null) {
    clip = keyword(clip, "clip", ["frame", "sphere"]);
    if (clip === "sphere") clip = { type: "Sphere" };
  }
  return clip;
}
function isArrowTable(value) {
  return value && typeof value.getChild === "function" && typeof value.toArray === "function" && value.schema && Array.isArray(value.schema.fields);
}
function isArrowVector(value) {
  return value && typeof value.toArray === "function" && value.type;
}
function isArrowDateType(type2) {
  return type2 && (type2.typeId === 8 || // date
  type2.typeId === 10) && // timestamp
  type2.unit === 1;
}

// node_modules/@observablehq/plot/src/scales/index.js
var position = Symbol("position");
var color2 = Symbol("color");
var radius = Symbol("radius");
var length2 = Symbol("length");
var opacity = Symbol("opacity");
var symbol = Symbol("symbol");
var projection2 = Symbol("projection");
var registry = /* @__PURE__ */ new Map([
  ["x", position],
  ["y", position],
  ["fx", position],
  ["fy", position],
  ["r", radius],
  ["color", color2],
  ["opacity", opacity],
  ["symbol", symbol],
  ["length", length2],
  ["projection", projection2]
]);
function isPosition(kind) {
  return kind === position || kind === projection2;
}
function hasNumericRange(kind) {
  return kind === position || kind === radius || kind === length2 || kind === opacity;
}

// node_modules/@observablehq/plot/src/symbol.js
var sqrt35 = Math.sqrt(3);
var sqrt4_3 = 2 / sqrt35;
var symbolHexagon = {
  draw(context, size) {
    const rx = Math.sqrt(size / Math.PI), ry = rx * sqrt4_3, hy = ry / 2;
    context.moveTo(0, ry);
    context.lineTo(rx, hy);
    context.lineTo(rx, -hy);
    context.lineTo(0, -ry);
    context.lineTo(-rx, -hy);
    context.lineTo(-rx, hy);
    context.closePath();
  }
};
var symbols = /* @__PURE__ */ new Map([
  ["asterisk", asterisk_default],
  ["circle", circle_default3],
  ["cross", cross_default2],
  ["diamond", diamond_default],
  ["diamond2", diamond2_default],
  ["hexagon", symbolHexagon],
  ["plus", plus_default],
  ["square", square_default],
  ["square2", square2_default],
  ["star", star_default],
  ["times", times_default],
  ["triangle", triangle_default],
  ["triangle2", triangle2_default],
  ["wye", wye_default]
]);
function isSymbolObject(value) {
  return value && typeof value.draw === "function";
}
function isSymbol(value) {
  if (isSymbolObject(value)) return true;
  if (typeof value !== "string") return false;
  return symbols.has(value.toLowerCase());
}
function maybeSymbol(symbol2) {
  if (symbol2 == null || isSymbolObject(symbol2)) return symbol2;
  const value = symbols.get(`${symbol2}`.toLowerCase());
  if (value) return value;
  throw new Error(`invalid symbol: ${symbol2}`);
}
function maybeSymbolChannel(symbol2) {
  if (symbol2 == null || isSymbolObject(symbol2)) return [void 0, symbol2];
  if (typeof symbol2 === "string") {
    const value = symbols.get(`${symbol2}`.toLowerCase());
    if (value) return [void 0, value];
  }
  return [symbol2, void 0];
}

// node_modules/@observablehq/plot/src/transforms/basic.js
function basic({ filter: f1, sort: s1, reverse: r1, transform: t13, initializer: i1, ...options } = {}, transform2) {
  if (t13 === void 0) {
    if (f1 != null) t13 = filterTransform(f1);
    if (s1 != null && !isDomainSort(s1)) t13 = composeTransform(t13, sortTransform(s1));
    if (r1) t13 = composeTransform(t13, reverseTransform);
  }
  if (transform2 != null && i1 != null) throw new Error("transforms cannot be applied after initializers");
  return {
    ...options,
    ...(s1 === null || isDomainSort(s1)) && { sort: s1 },
    transform: composeTransform(t13, transform2)
  };
}
function initializer({ filter: f1, sort: s1, reverse: r1, initializer: i1, ...options } = {}, initializer2) {
  if (i1 === void 0) {
    if (f1 != null) i1 = filterTransform(f1);
    if (s1 != null && !isDomainSort(s1)) i1 = composeInitializer(i1, sortTransform(s1));
    if (r1) i1 = composeInitializer(i1, reverseTransform);
  }
  return {
    ...options,
    ...(s1 === null || isDomainSort(s1)) && { sort: s1 },
    initializer: composeInitializer(i1, initializer2)
  };
}
function composeTransform(t13, t22) {
  if (t13 == null) return t22 === null ? void 0 : t22;
  if (t22 == null) return t13 === null ? void 0 : t13;
  return function(data, facets, plotOptions) {
    ({ data, facets } = t13.call(this, data, facets, plotOptions));
    return t22.call(this, dataify(data), facets, plotOptions);
  };
}
function composeInitializer(i1, i2) {
  if (i1 == null) return i2 === null ? void 0 : i2;
  if (i2 == null) return i1 === null ? void 0 : i1;
  return function(data, facets, channels, ...args) {
    let c1, d1, f1, c22, d2, f2;
    ({ data: d1 = data, facets: f1 = facets, channels: c1 } = i1.call(this, data, facets, channels, ...args));
    ({ data: d2 = d1, facets: f2 = f1, channels: c22 } = i2.call(this, d1, f1, { ...channels, ...c1 }, ...args));
    return { data: d2, facets: f2, channels: { ...c1, ...c22 } };
  };
}
function apply(options, t) {
  return (options.initializer != null ? initializer : basic)(options, t);
}
function filter3(test, options) {
  return apply(options, filterTransform(test));
}
function filterTransform(value) {
  return (data, facets) => {
    const V = valueof(data, value);
    return { data, facets: facets.map((I) => I.filter((i) => V[i])) };
  };
}
function reverse2({ sort: sort3, ...options } = {}) {
  return {
    ...apply(options, reverseTransform),
    sort: isDomainSort(sort3) ? sort3 : null
  };
}
function reverseTransform(data, facets) {
  return { data, facets: facets.map((I) => I.slice().reverse()) };
}
function shuffle2({ seed, sort: sort3, ...options } = {}) {
  return {
    ...apply(options, sortValue(seed == null ? Math.random : lcg(seed))),
    sort: isDomainSort(sort3) ? sort3 : null
  };
}
function sort2(order, { sort: sort3, ...options } = {}) {
  return {
    ...(isOptions(order) && order.channel !== void 0 ? initializer : apply)(options, sortTransform(order)),
    sort: isDomainSort(sort3) ? sort3 : null
  };
}
function sortTransform(value) {
  return (typeof value === "function" && value.length !== 1 ? sortData : sortValue)(value);
}
function sortData(compare) {
  return (data, facets) => {
    const compareData = isArray(data) ? (i, j) => compare(data[i], data[j]) : (i, j) => compare(data.get(i), data.get(j));
    return { data, facets: facets.map((I) => I.slice().sort(compareData)) };
  };
}
function sortValue(value) {
  let channel, order;
  ({ channel, value, order } = { ...maybeValue(value) });
  const negate2 = channel == null ? void 0 : channel.startsWith("-");
  if (negate2) channel = channel.slice(1);
  if (order === void 0) order = negate2 ? descendingDefined : ascendingDefined2;
  if (typeof order !== "function") {
    switch (`${order}`.toLowerCase()) {
      case "ascending":
        order = ascendingDefined2;
        break;
      case "descending":
        order = descendingDefined;
        break;
      default:
        throw new Error(`invalid order: ${order}`);
    }
  }
  return (data, facets, channels) => {
    let V;
    if (channel === void 0) {
      V = valueof(data, value);
    } else {
      if (channels === void 0) throw new Error("channel sort requires an initializer");
      V = channels[channel];
      if (!V) return {};
      V = V.value;
    }
    const compareValue = (i, j) => order(V[i], V[j]);
    return { data, facets: facets.map((I) => I.slice().sort(compareValue)) };
  };
}

// node_modules/@observablehq/plot/src/transforms/group.js
function groupZ(outputs, options) {
  return groupn(null, null, outputs, options);
}
function groupX(outputs = { y: "count" }, options = {}) {
  const { x: x3 = identity6 } = options;
  if (x3 == null) throw new Error("missing channel: x");
  return groupn(x3, null, outputs, options);
}
function groupY(outputs = { x: "count" }, options = {}) {
  const { y: y3 = identity6 } = options;
  if (y3 == null) throw new Error("missing channel: y");
  return groupn(null, y3, outputs, options);
}
function group2(outputs = { fill: "count" }, options = {}) {
  let { x: x3, y: y3 } = options;
  [x3, y3] = maybeTuple(x3, y3);
  if (x3 == null) throw new Error("missing channel: x");
  if (y3 == null) throw new Error("missing channel: y");
  return groupn(x3, y3, outputs, options);
}
function groupn(x3, y3, {
  data: reduceData = reduceIdentity,
  filter: filter4,
  sort: sort3,
  reverse: reverse3,
  ...outputs
  // output channel definitions
} = {}, inputs = {}) {
  outputs = maybeGroupOutputs(outputs, inputs);
  reduceData = maybeGroupReduce(reduceData, identity6);
  sort3 = sort3 == null ? void 0 : maybeGroupOutput("sort", sort3, inputs);
  filter4 = filter4 == null ? void 0 : maybeGroupEvaluator("filter", filter4, inputs);
  const [GX, setGX] = maybeColumn(x3);
  const [GY, setGY] = maybeColumn(y3);
  const {
    z,
    fill,
    stroke,
    x1: x12,
    x2: x22,
    // consumed if x is an output
    y1: y12,
    y2: y22,
    // consumed if y is an output
    ...options
  } = inputs;
  const [GZ, setGZ] = maybeColumn(z);
  const [vfill] = maybeColorChannel(fill);
  const [vstroke] = maybeColorChannel(stroke);
  const [GF, setGF] = maybeColumn(vfill);
  const [GS, setGS] = maybeColumn(vstroke);
  return {
    ..."z" in inputs && { z: GZ || z },
    ..."fill" in inputs && { fill: GF || fill },
    ..."stroke" in inputs && { stroke: GS || stroke },
    ...basic(options, (data, facets, plotOptions) => {
      const X3 = maybeApplyInterval(valueof(data, x3), plotOptions == null ? void 0 : plotOptions.x);
      const Y3 = maybeApplyInterval(valueof(data, y3), plotOptions == null ? void 0 : plotOptions.y);
      const Z = valueof(data, z);
      const F = valueof(data, vfill);
      const S = valueof(data, vstroke);
      const G = maybeSubgroup(outputs, { z: Z, fill: F, stroke: S });
      const groupFacets = [];
      const groupData = [];
      const GX2 = X3 && setGX([]);
      const GY2 = Y3 && setGY([]);
      const GZ2 = Z && setGZ([]);
      const GF2 = F && setGF([]);
      const GS2 = S && setGS([]);
      let i = 0;
      for (const o of outputs) o.initialize(data);
      if (sort3) sort3.initialize(data);
      if (filter4) filter4.initialize(data);
      for (const facet of facets) {
        const groupFacet = [];
        for (const o of outputs) o.scope("facet", facet);
        if (sort3) sort3.scope("facet", facet);
        if (filter4) filter4.scope("facet", facet);
        for (const [f, I] of maybeGroup(facet, G)) {
          for (const [y4, gg] of maybeGroup(I, Y3)) {
            for (const [x4, g] of maybeGroup(gg, X3)) {
              const extent3 = { data };
              if (X3) extent3.x = x4;
              if (Y3) extent3.y = y4;
              if (G) extent3.z = f;
              if (filter4 && !filter4.reduce(g, extent3)) continue;
              groupFacet.push(i++);
              groupData.push(reduceData.reduceIndex(g, data, extent3));
              if (X3) GX2.push(x4);
              if (Y3) GY2.push(y4);
              if (Z) GZ2.push(G === Z ? f : Z[g[0]]);
              if (F) GF2.push(G === F ? f : F[g[0]]);
              if (S) GS2.push(G === S ? f : S[g[0]]);
              for (const o of outputs) o.reduce(g, extent3);
              if (sort3) sort3.reduce(g, extent3);
            }
          }
        }
        groupFacets.push(groupFacet);
      }
      maybeSort(groupFacets, sort3, reverse3);
      return { data: groupData, facets: groupFacets };
    }),
    ...!hasOutput(outputs, "x") && (GX ? { x: GX } : { x1: x12, x2: x22 }),
    ...!hasOutput(outputs, "y") && (GY ? { y: GY } : { y1: y12, y2: y22 }),
    ...Object.fromEntries(outputs.map(({ name, output }) => [name, output]))
  };
}
function hasOutput(outputs, ...names) {
  for (const { name } of outputs) {
    if (names.includes(name)) {
      return true;
    }
  }
  return false;
}
function maybeOutputs(outputs, inputs, asOutput = maybeOutput) {
  const entries = Object.entries(outputs);
  if (inputs.title != null && outputs.title === void 0) entries.push(["title", reduceTitle]);
  if (inputs.href != null && outputs.href === void 0) entries.push(["href", reduceFirst]);
  return entries.filter(([, reduce2]) => reduce2 !== void 0).map(([name, reduce2]) => reduce2 === null ? nullOutput(name) : asOutput(name, reduce2, inputs));
}
function maybeOutput(name, reduce2, inputs, asEvaluator = maybeEvaluator) {
  let scale3;
  if (isObject(reduce2) && "reduce" in reduce2) scale3 = reduce2.scale, reduce2 = reduce2.reduce;
  const evaluator = asEvaluator(name, reduce2, inputs);
  const [output, setOutput] = column(evaluator.label);
  let O;
  return {
    name,
    output: scale3 === void 0 ? output : { value: output, scale: scale3 },
    initialize(data) {
      evaluator.initialize(data);
      O = setOutput([]);
    },
    scope(scope, I) {
      evaluator.scope(scope, I);
    },
    reduce(I, extent3) {
      O.push(evaluator.reduce(I, extent3));
    }
  };
}
function nullOutput(name) {
  return { name, initialize() {
  }, scope() {
  }, reduce() {
  } };
}
function maybeEvaluator(name, reduce2, inputs, asReduce = maybeReduce) {
  const input = maybeInput(name, inputs);
  const reducer2 = asReduce(reduce2, input);
  let V, context;
  return {
    label: labelof(reducer2 === reduceCount ? null : input, reducer2.label),
    initialize(data) {
      V = input === void 0 ? data : valueof(data, input);
      if (reducer2.scope === "data") {
        context = reducer2.reduceIndex(range2(data), V);
      }
    },
    scope(scope, I) {
      if (reducer2.scope === scope) {
        context = reducer2.reduceIndex(I, V);
      }
    },
    reduce(I, extent3) {
      return reducer2.scope == null ? reducer2.reduceIndex(I, V, extent3) : reducer2.reduceIndex(I, V, context, extent3);
    }
  };
}
function maybeGroup(I, X3) {
  return X3 ? group(I, (i) => X3[i]) : [[, I]];
}
function maybeReduce(reduce2, value, fallback = invalidReduce) {
  if (reduce2 == null) return fallback(reduce2);
  if (typeof reduce2.reduceIndex === "function") return reduce2;
  if (typeof reduce2.reduce === "function" && isObject(reduce2)) return reduceReduce(reduce2);
  if (typeof reduce2 === "function") return reduceFunction(reduce2);
  if (/^p\d{2}$/i.test(reduce2)) return reduceAccessor(percentile(reduce2));
  switch (`${reduce2}`.toLowerCase()) {
    case "first":
      return reduceFirst;
    case "last":
      return reduceLast;
    case "identity":
      return reduceIdentity;
    case "count":
      return reduceCount;
    case "distinct":
      return reduceDistinct;
    case "sum":
      return value == null ? reduceCount : reduceSum;
    case "proportion":
      return reduceProportion(value, "data");
    case "proportion-facet":
      return reduceProportion(value, "facet");
    case "deviation":
      return reduceAccessor(deviation);
    case "min":
      return reduceAccessor(min);
    case "min-index":
      return reduceAccessor(minIndex);
    case "max":
      return reduceAccessor(max);
    case "max-index":
      return reduceAccessor(maxIndex);
    case "mean":
      return reduceMaybeTemporalAccessor(mean);
    case "median":
      return reduceMaybeTemporalAccessor(median);
    case "variance":
      return reduceAccessor(variance);
    case "mode":
      return reduceAccessor(mode);
  }
  return fallback(reduce2);
}
function invalidReduce(reduce2) {
  throw new Error(`invalid reduce: ${reduce2}`);
}
function maybeGroupOutputs(outputs, inputs) {
  return maybeOutputs(outputs, inputs, maybeGroupOutput);
}
function maybeGroupOutput(name, reduce2, inputs) {
  return maybeOutput(name, reduce2, inputs, maybeGroupEvaluator);
}
function maybeGroupEvaluator(name, reduce2, inputs) {
  return maybeEvaluator(name, reduce2, inputs, maybeGroupReduce);
}
function maybeGroupReduce(reduce2, value) {
  return maybeReduce(reduce2, value, maybeGroupReduceFallback);
}
function maybeGroupReduceFallback(reduce2) {
  switch (`${reduce2}`.toLowerCase()) {
    case "x":
      return reduceX;
    case "y":
      return reduceY;
    case "z":
      return reduceZ;
  }
  throw new Error(`invalid group reduce: ${reduce2}`);
}
function maybeSubgroup(outputs, inputs) {
  for (const name in inputs) {
    const value = inputs[name];
    if (value !== void 0 && !outputs.some((o) => o.name === name)) {
      return value;
    }
  }
}
function maybeSort(facets, sort3, reverse3) {
  if (sort3) {
    const S = sort3.output.transform();
    const compare = (i, j) => ascendingDefined2(S[i], S[j]);
    facets.forEach((f) => f.sort(compare));
  }
  if (reverse3) {
    facets.forEach((f) => f.reverse());
  }
}
function reduceReduce(reduce2) {
  console.warn("deprecated reduce interface; implement reduceIndex instead.");
  return { ...reduce2, reduceIndex: reduce2.reduce.bind(reduce2) };
}
function reduceFunction(f) {
  return {
    reduceIndex(I, X3, extent3) {
      return f(take(X3, I), extent3);
    }
  };
}
function reduceAccessor(f) {
  return {
    reduceIndex(I, X3) {
      return f(I, (i) => X3[i]);
    }
  };
}
function reduceMaybeTemporalAccessor(f) {
  return {
    reduceIndex(I, X3) {
      const x3 = f(I, (i) => X3[i]);
      return isTemporal(X3) ? new Date(x3) : x3;
    }
  };
}
var reduceIdentity = {
  reduceIndex(I, X3) {
    return take(X3, I);
  }
};
var reduceFirst = {
  reduceIndex(I, X3) {
    return X3[I[0]];
  }
};
var reduceTitle = {
  reduceIndex(I, X3) {
    const n = 5;
    const groups2 = sort(
      rollup(
        I,
        (V) => V.length,
        (i) => X3[i]
      ),
      second2
    );
    const top2 = groups2.slice(-n).reverse();
    if (top2.length < groups2.length) {
      const bottom2 = groups2.slice(0, 1 - n);
      top2[n - 1] = [`… ${bottom2.length.toLocaleString("en-US")} more`, sum(bottom2, second2)];
    }
    return top2.map(([key, value]) => `${key} (${value.toLocaleString("en-US")})`).join("\n");
  }
};
var reduceLast = {
  reduceIndex(I, X3) {
    return X3[I[I.length - 1]];
  }
};
var reduceCount = {
  label: "Frequency",
  reduceIndex(I) {
    return I.length;
  }
};
var reduceDistinct = {
  label: "Distinct",
  reduceIndex(I, X3) {
    const s2 = new InternSet();
    for (const i of I) s2.add(X3[i]);
    return s2.size;
  }
};
var reduceSum = reduceAccessor(sum);
function reduceProportion(value, scope) {
  return value == null ? { scope, label: "Frequency", reduceIndex: (I, V, basis2 = 1) => I.length / basis2 } : { scope, reduceIndex: (I, V, basis2 = 1) => sum(I, (i) => V[i]) / basis2 };
}
var reduceX = {
  reduceIndex(I, X3, { x: x3 }) {
    return x3;
  }
};
var reduceY = {
  reduceIndex(I, X3, { y: y3 }) {
    return y3;
  }
};
var reduceZ = {
  reduceIndex(I, X3, { z }) {
    return z;
  }
};
function find2(test) {
  if (typeof test !== "function") throw new Error(`invalid test function: ${test}`);
  return {
    reduceIndex(I, V, { data }) {
      return V[I.find(isArray(data) ? (i) => test(data[i], i, data) : (i) => test(data.get(i), i, data))];
    }
  };
}

// node_modules/@observablehq/plot/src/channel.js
function createChannel(data, { scale: scale3, type: type2, value, filter: filter4, hint, label = labelof(value) }, name) {
  if (hint === void 0 && typeof (value == null ? void 0 : value.transform) === "function") hint = value.hint;
  return inferChannelScale(name, {
    scale: scale3,
    type: type2,
    value: valueof(data, value),
    label,
    filter: filter4,
    hint
  });
}
function createChannels(channels, data) {
  return Object.fromEntries(
    Object.entries(channels).map(([name, channel]) => [name, createChannel(data, channel, name)])
  );
}
function valueObject(channels, scales) {
  const values2 = Object.fromEntries(
    Object.entries(channels).map(([name, { scale: scaleName, value }]) => {
      const scale3 = scaleName == null ? null : scales[scaleName];
      return [name, scale3 == null ? value : map4(value, scale3)];
    })
  );
  values2.channels = channels;
  return values2;
}
function inferChannelScale(name, channel) {
  const { scale: scale3, value } = channel;
  if (scale3 === true || scale3 === "auto") {
    switch (name) {
      case "fill":
      case "stroke":
      case "color":
        channel.scale = scale3 !== true && isEvery(value, isColor) ? null : "color";
        channel.defaultScale = "color";
        break;
      case "fillOpacity":
      case "strokeOpacity":
      case "opacity":
        channel.scale = scale3 !== true && isEvery(value, isOpacity) ? null : "opacity";
        channel.defaultScale = "opacity";
        break;
      case "symbol":
        if (scale3 !== true && isEvery(value, isSymbol)) {
          channel.scale = null;
          channel.value = map4(value, maybeSymbol);
        } else {
          channel.scale = "symbol";
        }
        channel.defaultScale = "symbol";
        break;
      default:
        channel.scale = registry.has(name) ? name : null;
        break;
    }
  } else if (scale3 === false) {
    channel.scale = null;
  } else if (scale3 != null && !registry.has(scale3)) {
    throw new Error(`unknown scale: ${scale3}`);
  }
  return channel;
}
function channelDomain(data, facets, channels, facetChannels, options) {
  const { order: defaultOrder, reverse: defaultReverse, reduce: defaultReduce = true, limit: defaultLimit } = options;
  for (const x3 in options) {
    if (!registry.has(x3)) continue;
    let { value: y3, order = defaultOrder, reverse: reverse3 = defaultReverse, reduce: reduce2 = defaultReduce, limit = defaultLimit } = maybeValue(options[x3]);
    const negate2 = y3 == null ? void 0 : y3.startsWith("-");
    if (negate2) y3 = y3.slice(1);
    order = order === void 0 ? negate2 !== (y3 === "width" || y3 === "height") ? descendingGroup : ascendingGroup : maybeOrder(order);
    if (reduce2 == null || reduce2 === false) continue;
    const X3 = x3 === "fx" || x3 === "fy" ? reindexFacetChannel(facets, facetChannels[x3]) : findScaleChannel(channels, x3);
    if (!X3) throw new Error(`missing channel for scale: ${x3}`);
    const XV = X3.value;
    const [lo = 0, hi = Infinity] = isIterable(limit) ? limit : limit < 0 ? [limit] : [0, limit];
    if (y3 == null) {
      X3.domain = () => {
        let domain = Array.from(new InternSet(XV));
        if (reverse3) domain = domain.reverse();
        if (lo !== 0 || hi !== Infinity) domain = domain.slice(lo, hi);
        return domain;
      };
    } else {
      const YV = y3 === "data" ? data : y3 === "height" ? difference2(channels, "y1", "y2") : y3 === "width" ? difference2(channels, "x1", "x2") : values(channels, y3, y3 === "y" ? "y2" : y3 === "x" ? "x2" : void 0);
      const reducer2 = maybeReduce(reduce2 === true ? "max" : reduce2, YV);
      X3.domain = () => {
        let domain = rollups(
          range2(XV),
          (I) => reducer2.reduceIndex(I, YV),
          (i) => XV[i]
        );
        if (order) domain.sort(order);
        if (reverse3) domain.reverse();
        if (lo !== 0 || hi !== Infinity) domain = domain.slice(lo, hi);
        return domain.map(first);
      };
    }
  }
}
function findScaleChannel(channels, scale3) {
  for (const name in channels) {
    const channel = channels[name];
    if (channel.scale === scale3) return channel;
  }
}
function reindexFacetChannel(facets, channel) {
  const originalFacets = facets.original;
  if (originalFacets === facets) return channel;
  const V1 = channel.value;
  const V2 = channel.value = [];
  for (let i = 0; i < originalFacets.length; ++i) {
    const vi = V1[originalFacets[i][0]];
    for (const j of facets[i]) V2[j] = vi;
  }
  return channel;
}
function difference2(channels, k1, k2) {
  const X13 = values(channels, k1);
  const X23 = values(channels, k2);
  return map4(X23, (x22, i) => Math.abs(x22 - X13[i]), Float64Array);
}
function values(channels, name, alias) {
  let channel = channels[name];
  if (!channel && alias !== void 0) channel = channels[alias];
  if (channel) return channel.value;
  throw new Error(`missing channel: ${name}`);
}
function maybeOrder(order) {
  if (order == null || typeof order === "function") return order;
  switch (`${order}`.toLowerCase()) {
    case "ascending":
      return ascendingGroup;
    case "descending":
      return descendingGroup;
  }
  throw new Error(`invalid order: ${order}`);
}
function ascendingGroup([ak, av], [bk, bv]) {
  return ascendingDefined2(av, bv) || ascendingDefined2(ak, bk);
}
function descendingGroup([ak, av], [bk, bv]) {
  return descendingDefined(av, bv) || ascendingDefined2(ak, bk);
}
function getSource(channels, key) {
  let channel = channels[key];
  if (!channel) return;
  while (channel.source) channel = channel.source;
  return channel.source === null ? null : channel;
}

// node_modules/@observablehq/plot/src/scales/schemes.js
var categoricalSchemes = /* @__PURE__ */ new Map([
  ["accent", Accent_default],
  ["category10", category10_default],
  ["dark2", Dark2_default],
  ["observable10", observable10_default],
  ["paired", Paired_default],
  ["pastel1", Pastel1_default],
  ["pastel2", Pastel2_default],
  ["set1", Set1_default],
  ["set2", Set2_default],
  ["set3", Set3_default],
  ["tableau10", Tableau10_default]
]);
function isCategoricalScheme(scheme28) {
  return scheme28 != null && categoricalSchemes.has(`${scheme28}`.toLowerCase());
}
var ordinalSchemes = new Map([
  ...categoricalSchemes,
  // diverging
  ["brbg", scheme112(scheme, BrBG_default)],
  ["prgn", scheme112(scheme2, PRGn_default)],
  ["piyg", scheme112(scheme3, PiYG_default)],
  ["puor", scheme112(scheme4, PuOr_default)],
  ["rdbu", scheme112(scheme5, RdBu_default)],
  ["rdgy", scheme112(scheme6, RdGy_default)],
  ["rdylbu", scheme112(scheme7, RdYlBu_default)],
  ["rdylgn", scheme112(scheme8, RdYlGn_default)],
  ["spectral", scheme112(scheme9, Spectral_default)],
  // reversed diverging (for temperature data)
  ["burd", scheme11r(scheme5, RdBu_default)],
  ["buylrd", scheme11r(scheme7, RdYlBu_default)],
  // sequential (single-hue)
  ["blues", scheme92(scheme22, Blues_default)],
  ["greens", scheme92(scheme23, Greens_default)],
  ["greys", scheme92(scheme24, Greys_default)],
  ["oranges", scheme92(scheme27, Oranges_default)],
  ["purples", scheme92(scheme25, Purples_default)],
  ["reds", scheme92(scheme26, Reds_default)],
  // sequential (multi-hue)
  ["turbo", schemei(turbo_default)],
  ["viridis", schemei(viridis_default)],
  ["magma", schemei(magma)],
  ["inferno", schemei(inferno)],
  ["plasma", schemei(plasma)],
  ["cividis", schemei(cividis_default)],
  ["cubehelix", schemei(cubehelix_default2)],
  ["warm", schemei(warm)],
  ["cool", schemei(cool)],
  ["bugn", scheme92(scheme10, BuGn_default)],
  ["bupu", scheme92(scheme11, BuPu_default)],
  ["gnbu", scheme92(scheme12, GnBu_default)],
  ["orrd", scheme92(scheme13, OrRd_default)],
  ["pubu", scheme92(scheme15, PuBu_default)],
  ["pubugn", scheme92(scheme14, PuBuGn_default)],
  ["purd", scheme92(scheme16, PuRd_default)],
  ["rdpu", scheme92(scheme17, RdPu_default)],
  ["ylgn", scheme92(scheme19, YlGn_default)],
  ["ylgnbu", scheme92(scheme18, YlGnBu_default)],
  ["ylorbr", scheme92(scheme20, YlOrBr_default)],
  ["ylorrd", scheme92(scheme21, YlOrRd_default)],
  // cyclical
  ["rainbow", schemeicyclical(rainbow_default)],
  ["sinebow", schemeicyclical(sinebow_default)]
]);
function scheme92(scheme28, interpolate) {
  return ({ length: n }) => {
    if (n === 1) return [scheme28[3][1]];
    if (n === 2) return [scheme28[3][1], scheme28[3][2]];
    n = Math.max(3, Math.floor(n));
    return n > 9 ? quantize_default(interpolate, n) : scheme28[n];
  };
}
function scheme112(scheme28, interpolate) {
  return ({ length: n }) => {
    if (n === 2) return [scheme28[3][0], scheme28[3][2]];
    n = Math.max(3, Math.floor(n));
    return n > 11 ? quantize_default(interpolate, n) : scheme28[n];
  };
}
function scheme11r(scheme28, interpolate) {
  return ({ length: n }) => {
    if (n === 2) return [scheme28[3][2], scheme28[3][0]];
    n = Math.max(3, Math.floor(n));
    return n > 11 ? quantize_default((t) => interpolate(1 - t), n) : scheme28[n].slice().reverse();
  };
}
function schemei(interpolate) {
  return ({ length: n }) => quantize_default(interpolate, Math.max(2, Math.floor(n)));
}
function schemeicyclical(interpolate) {
  return ({ length: n }) => quantize_default(interpolate, Math.floor(n) + 1).slice(0, -1);
}
function ordinalScheme(scheme28) {
  const s2 = `${scheme28}`.toLowerCase();
  if (!ordinalSchemes.has(s2)) throw new Error(`unknown ordinal scheme: ${s2}`);
  return ordinalSchemes.get(s2);
}
function ordinalRange(scheme28, length3) {
  const s2 = ordinalScheme(scheme28);
  const r = typeof s2 === "function" ? s2({ length: length3 }) : s2;
  return r.length !== length3 ? r.slice(0, length3) : r;
}
function maybeBooleanRange(domain, scheme28 = "greys") {
  const range3 = /* @__PURE__ */ new Set();
  const [f, t] = ordinalRange(scheme28, 2);
  for (const value of domain) {
    if (value == null) continue;
    if (value === true) range3.add(t);
    else if (value === false) range3.add(f);
    else return;
  }
  return [...range3];
}
var quantitativeSchemes = /* @__PURE__ */ new Map([
  // diverging
  ["brbg", BrBG_default],
  ["prgn", PRGn_default],
  ["piyg", PiYG_default],
  ["puor", PuOr_default],
  ["rdbu", RdBu_default],
  ["rdgy", RdGy_default],
  ["rdylbu", RdYlBu_default],
  ["rdylgn", RdYlGn_default],
  ["spectral", Spectral_default],
  // reversed diverging (for temperature data)
  ["burd", (t) => RdBu_default(1 - t)],
  ["buylrd", (t) => RdYlBu_default(1 - t)],
  // sequential (single-hue)
  ["blues", Blues_default],
  ["greens", Greens_default],
  ["greys", Greys_default],
  ["purples", Purples_default],
  ["reds", Reds_default],
  ["oranges", Oranges_default],
  // sequential (multi-hue)
  ["turbo", turbo_default],
  ["viridis", viridis_default],
  ["magma", magma],
  ["inferno", inferno],
  ["plasma", plasma],
  ["cividis", cividis_default],
  ["cubehelix", cubehelix_default2],
  ["warm", warm],
  ["cool", cool],
  ["bugn", BuGn_default],
  ["bupu", BuPu_default],
  ["gnbu", GnBu_default],
  ["orrd", OrRd_default],
  ["pubugn", PuBuGn_default],
  ["pubu", PuBu_default],
  ["purd", PuRd_default],
  ["rdpu", RdPu_default],
  ["ylgnbu", YlGnBu_default],
  ["ylgn", YlGn_default],
  ["ylorbr", YlOrBr_default],
  ["ylorrd", YlOrRd_default],
  // cyclical
  ["rainbow", rainbow_default],
  ["sinebow", sinebow_default]
]);
function quantitativeScheme(scheme28) {
  const s2 = `${scheme28}`.toLowerCase();
  if (!quantitativeSchemes.has(s2)) throw new Error(`unknown quantitative scheme: ${s2}`);
  return quantitativeSchemes.get(s2);
}
var divergingSchemes = /* @__PURE__ */ new Set([
  "brbg",
  "prgn",
  "piyg",
  "puor",
  "rdbu",
  "rdgy",
  "rdylbu",
  "rdylgn",
  "spectral",
  "burd",
  "buylrd"
]);
function isDivergingScheme(scheme28) {
  return scheme28 != null && divergingSchemes.has(`${scheme28}`.toLowerCase());
}

// node_modules/@observablehq/plot/src/scales/quantitative.js
var flip = (i) => (t) => i(1 - t);
var unit2 = [0, 1];
var interpolators = /* @__PURE__ */ new Map([
  // numbers
  ["number", number_default],
  // color spaces
  ["rgb", rgb_default],
  ["hsl", hsl_default],
  ["hcl", hcl_default],
  ["lab", lab2]
]);
function maybeInterpolator(interpolate) {
  const i = `${interpolate}`.toLowerCase();
  if (!interpolators.has(i)) throw new Error(`unknown interpolator: ${i}`);
  return interpolators.get(i);
}
function createScaleQ(key, scale3, channels, {
  type: type2,
  nice: nice3,
  clamp,
  zero: zero3,
  domain = inferAutoDomain(key, channels),
  unknown,
  round: round2,
  scheme: scheme28,
  interval: interval2,
  range: range3 = registry.get(key) === radius ? inferRadialRange(channels, domain) : registry.get(key) === length2 ? inferLengthRange(channels, domain) : registry.get(key) === opacity ? unit2 : void 0,
  interpolate = registry.get(key) === color2 ? scheme28 == null && range3 !== void 0 ? rgb_default : quantitativeScheme(scheme28 !== void 0 ? scheme28 : type2 === "cyclical" ? "rainbow" : "turbo") : round2 ? round_default : number_default,
  reverse: reverse3
}) {
  domain = maybeRepeat(domain);
  interval2 = maybeRangeInterval(interval2, type2);
  if (type2 === "cyclical" || type2 === "sequential") type2 = "linear";
  if (typeof interpolate !== "function") interpolate = maybeInterpolator(interpolate);
  reverse3 = !!reverse3;
  if (range3 !== void 0) {
    const n = domain.length;
    const m = (range3 = maybeRepeat(range3)).length;
    if (n !== m) {
      if (interpolate.length === 1) throw new Error("invalid piecewise interpolator");
      interpolate = piecewise(interpolate, range3);
      range3 = void 0;
    }
  }
  if (interpolate.length === 1) {
    if (reverse3) {
      interpolate = flip(interpolate);
      reverse3 = false;
    }
    if (range3 === void 0) {
      range3 = Float64Array.from(domain, (_, i) => i / (domain.length - 1));
      if (range3.length === 2) range3 = unit2;
    }
    scale3.interpolate((range3 === unit2 ? constant2 : interpolatePiecewise)(interpolate));
  } else {
    scale3.interpolate(interpolate);
  }
  if (zero3) {
    const [min4, max5] = extent(domain);
    if (min4 > 0 || max5 < 0) {
      domain = slice5(domain);
      const o = orderof(domain) || 1;
      if (o === Math.sign(min4)) domain[0] = 0;
      else domain[domain.length - 1] = 0;
    }
  }
  if (reverse3) domain = reverse(domain);
  scale3.domain(domain).unknown(unknown);
  if (nice3) scale3.nice(maybeNice(nice3, type2)), domain = scale3.domain();
  if (range3 !== void 0) scale3.range(range3);
  if (clamp) scale3.clamp(clamp);
  return { type: type2, domain, range: range3, scale: scale3, interpolate, interval: interval2 };
}
function maybeRepeat(values2) {
  values2 = arrayify2(values2);
  return values2.length >= 2 ? values2 : [values2[0], values2[0]];
}
function maybeNice(nice3, type2) {
  return nice3 === true ? void 0 : typeof nice3 === "number" ? nice3 : maybeNiceInterval(nice3, type2);
}
function createScaleLinear(key, channels, options) {
  return createScaleQ(key, linear3(), channels, options);
}
function createScaleSqrt(key, channels, options) {
  return createScalePow(key, channels, { ...options, exponent: 0.5 });
}
function createScalePow(key, channels, { exponent: exponent2 = 1, ...options }) {
  return createScaleQ(key, pow3().exponent(exponent2), channels, { ...options, type: "pow" });
}
function createScaleLog(key, channels, { base = 10, domain = inferLogDomain(channels), ...options }) {
  return createScaleQ(key, log2().base(base), channels, { ...options, domain });
}
function createScaleSymlog(key, channels, { constant: constant3 = 1, ...options }) {
  return createScaleQ(key, symlog().constant(constant3), channels, options);
}
function createScaleQuantile(key, channels, {
  range: range3,
  quantiles = range3 === void 0 ? 5 : (range3 = [...range3]).length,
  // deprecated; use n instead
  n = quantiles,
  scheme: scheme28 = "rdylbu",
  domain = inferQuantileDomain(channels),
  unknown,
  interpolate,
  reverse: reverse3
}) {
  if (range3 === void 0) {
    range3 = interpolate !== void 0 ? quantize_default(interpolate, n) : registry.get(key) === color2 ? ordinalRange(scheme28, n) : void 0;
  }
  if (domain.length > 0) {
    domain = quantile2(domain, range3 === void 0 ? { length: n } : range3).quantiles();
  }
  return createScaleThreshold(key, channels, { domain, range: range3, reverse: reverse3, unknown });
}
function createScaleQuantize(key, channels, {
  range: range3,
  n = range3 === void 0 ? 5 : (range3 = [...range3]).length,
  scheme: scheme28 = "rdylbu",
  domain = inferAutoDomain(key, channels),
  unknown,
  interpolate,
  reverse: reverse3
}) {
  const [min4, max5] = extent(domain);
  let thresholds;
  if (range3 === void 0) {
    thresholds = ticks(min4, max5, n);
    if (thresholds[0] <= min4) thresholds.splice(0, 1);
    if (thresholds[thresholds.length - 1] >= max5) thresholds.pop();
    n = thresholds.length + 1;
    range3 = interpolate !== void 0 ? quantize_default(interpolate, n) : registry.get(key) === color2 ? ordinalRange(scheme28, n) : void 0;
  } else {
    thresholds = quantize_default(number_default(min4, max5), n + 1).slice(1, -1);
    if (min4 instanceof Date) thresholds = thresholds.map((x3) => new Date(x3));
  }
  if (orderof(arrayify2(domain)) < 0) thresholds.reverse();
  return createScaleThreshold(key, channels, { domain: thresholds, range: range3, reverse: reverse3, unknown });
}
function createScaleThreshold(key, channels, {
  domain = [0],
  // explicit thresholds in ascending order
  unknown,
  scheme: scheme28 = "rdylbu",
  interpolate,
  range: range3 = interpolate !== void 0 ? quantize_default(interpolate, domain.length + 1) : registry.get(key) === color2 ? ordinalRange(scheme28, domain.length + 1) : void 0,
  reverse: reverse3
}) {
  domain = arrayify2(domain);
  const sign3 = orderof(domain);
  if (!isNaN(sign3) && !isOrdered(domain, sign3)) throw new Error(`the ${key} scale has a non-monotonic domain`);
  if (reverse3) range3 = reverse(range3);
  return {
    type: "threshold",
    scale: threshold(sign3 < 0 ? reverse(domain) : domain, range3 === void 0 ? [] : range3).unknown(unknown),
    domain,
    range: range3
  };
}
function isOrdered(domain, sign3) {
  for (let i = 1, n = domain.length, d = domain[0]; i < n; ++i) {
    const s2 = descending(d, d = domain[i]);
    if (s2 !== 0 && s2 !== sign3) return false;
  }
  return true;
}
function createScaleIdentity(key) {
  return { type: "identity", scale: hasNumericRange(registry.get(key)) ? identity4() : (d) => d };
}
function inferDomain(channels, f = finite2) {
  return channels.length ? [
    min(channels, ({ value }) => value === void 0 ? value : min(value, f)),
    max(channels, ({ value }) => value === void 0 ? value : max(value, f))
  ] : [0, 1];
}
function inferAutoDomain(key, channels) {
  const type2 = registry.get(key);
  return (type2 === radius || type2 === opacity || type2 === length2 ? inferZeroDomain : inferDomain)(channels);
}
function inferZeroDomain(channels) {
  return [0, channels.length ? max(channels, ({ value }) => value === void 0 ? value : max(value, finite2)) : 1];
}
function inferRadialRange(channels, domain) {
  const hint = channels.find(({ radius: radius2 }) => radius2 !== void 0);
  if (hint !== void 0) return [0, hint.radius];
  const h25 = quantile(channels, 0.5, ({ value }) => value === void 0 ? NaN : quantile(value, 0.25, positive));
  const range3 = domain.map((d) => 3 * Math.sqrt(d / h25));
  const k2 = 30 / max(range3);
  return k2 < 1 ? range3.map((r) => r * k2) : range3;
}
function inferLengthRange(channels, domain) {
  const h50 = median(channels, ({ value }) => value === void 0 ? NaN : median(value, Math.abs));
  const range3 = domain.map((d) => 12 * d / h50);
  const k2 = 60 / max(range3);
  return k2 < 1 ? range3.map((r) => r * k2) : range3;
}
function inferLogDomain(channels) {
  for (const { value } of channels) {
    if (value !== void 0) {
      for (let v2 of value) {
        if (v2 > 0) return inferDomain(channels, positive);
        if (v2 < 0) return inferDomain(channels, negative);
      }
    }
  }
  return [1, 10];
}
function inferQuantileDomain(channels) {
  const domain = [];
  for (const { value } of channels) {
    if (value === void 0) continue;
    for (const v2 of value) domain.push(v2);
  }
  return domain;
}
function interpolatePiecewise(interpolate) {
  return (i, j) => (t) => interpolate(i + t * (j - i));
}

// node_modules/@observablehq/plot/src/warnings.js
var warnings = 0;
var lastMessage;
function consumeWarnings() {
  const w = warnings;
  warnings = 0;
  lastMessage = void 0;
  return w;
}
function warn(message) {
  if (message === lastMessage) return;
  lastMessage = message;
  console.warn(message);
  ++warnings;
}

// node_modules/@observablehq/plot/src/scales/diverging.js
function createScaleD(key, scale3, transform2, channels, {
  type: type2,
  nice: nice3,
  clamp,
  domain = inferDomain(channels),
  unknown,
  pivot = 0,
  scheme: scheme28,
  range: range3,
  symmetric = true,
  interpolate = registry.get(key) === color2 ? scheme28 == null && range3 !== void 0 ? rgb_default : quantitativeScheme(scheme28 !== void 0 ? scheme28 : "rdbu") : number_default,
  reverse: reverse3
}) {
  pivot = +pivot;
  domain = arrayify2(domain);
  let [min4, max5] = domain;
  if (domain.length > 2) warn(`Warning: the diverging ${key} scale domain contains extra elements.`);
  if (descending(min4, max5) < 0) [min4, max5] = [max5, min4], reverse3 = !reverse3;
  min4 = Math.min(min4, pivot);
  max5 = Math.max(max5, pivot);
  if (typeof interpolate !== "function") {
    interpolate = maybeInterpolator(interpolate);
  }
  if (range3 !== void 0) {
    interpolate = interpolate.length === 1 ? interpolatePiecewise(interpolate)(...range3) : piecewise(interpolate, range3);
  }
  if (reverse3) interpolate = flip(interpolate);
  if (symmetric) {
    const mid2 = transform2.apply(pivot);
    const mindelta = mid2 - transform2.apply(min4);
    const maxdelta = transform2.apply(max5) - mid2;
    if (mindelta < maxdelta) min4 = transform2.invert(mid2 - maxdelta);
    else if (mindelta > maxdelta) max5 = transform2.invert(mid2 + mindelta);
  }
  scale3.domain([min4, pivot, max5]).unknown(unknown).interpolator(interpolate);
  if (clamp) scale3.clamp(clamp);
  if (nice3) scale3.nice(nice3);
  return { type: type2, domain: [min4, max5], pivot, interpolate, scale: scale3 };
}
function createScaleDiverging(key, channels, options) {
  return createScaleD(key, diverging(), transformIdentity, channels, options);
}
function createScaleDivergingSqrt(key, channels, options) {
  return createScaleDivergingPow(key, channels, { ...options, exponent: 0.5 });
}
function createScaleDivergingPow(key, channels, { exponent: exponent2 = 1, ...options }) {
  return createScaleD(key, divergingPow().exponent(exponent2 = +exponent2), transformPow2(exponent2), channels, {
    ...options,
    type: "diverging-pow"
  });
}
function createScaleDivergingLog(key, channels, { base = 10, pivot = 1, domain = inferDomain(channels, pivot < 0 ? negative : positive), ...options }) {
  return createScaleD(key, divergingLog().base(base = +base), transformLog2, channels, {
    domain,
    pivot,
    ...options
  });
}
function createScaleDivergingSymlog(key, channels, { constant: constant3 = 1, ...options }) {
  return createScaleD(
    key,
    divergingSymlog().constant(constant3 = +constant3),
    transformSymlog2(constant3),
    channels,
    options
  );
}
var transformIdentity = {
  apply(x3) {
    return x3;
  },
  invert(x3) {
    return x3;
  }
};
var transformLog2 = {
  apply: Math.log,
  invert: Math.exp
};
var transformSqrt2 = {
  apply(x3) {
    return Math.sign(x3) * Math.sqrt(Math.abs(x3));
  },
  invert(x3) {
    return Math.sign(x3) * (x3 * x3);
  }
};
function transformPow2(exponent2) {
  return exponent2 === 0.5 ? transformSqrt2 : {
    apply(x3) {
      return Math.sign(x3) * Math.pow(Math.abs(x3), exponent2);
    },
    invert(x3) {
      return Math.sign(x3) * Math.pow(Math.abs(x3), 1 / exponent2);
    }
  };
}
function transformSymlog2(constant3) {
  return {
    apply(x3) {
      return Math.sign(x3) * Math.log1p(Math.abs(x3 / constant3));
    },
    invert(x3) {
      return Math.sign(x3) * Math.expm1(Math.abs(x3)) * constant3;
    }
  };
}

// node_modules/@observablehq/plot/src/scales/temporal.js
function createScaleT(key, scale3, channels, options) {
  return createScaleQ(key, scale3, channels, options);
}
function createScaleTime(key, channels, options) {
  return createScaleT(key, time(), channels, options);
}
function createScaleUtc(key, channels, options) {
  return createScaleT(key, utcTime(), channels, options);
}

// node_modules/@observablehq/plot/src/scales/ordinal.js
var ordinalImplicit = Symbol("ordinal");
function createScaleO(key, scale3, channels, { type: type2, interval: interval2, domain, range: range3, reverse: reverse3, hint }) {
  interval2 = maybeRangeInterval(interval2, type2);
  if (domain === void 0) domain = inferDomain2(channels, interval2, key);
  if (type2 === "categorical" || type2 === ordinalImplicit) type2 = "ordinal";
  if (reverse3) domain = reverse(domain);
  domain = scale3.domain(domain).domain();
  if (range3 !== void 0) {
    if (typeof range3 === "function") range3 = range3(domain);
    scale3.range(range3);
  }
  return { type: type2, domain, range: range3, scale: scale3, hint, interval: interval2 };
}
function createScaleOrdinal(key, channels, { type: type2, interval: interval2, domain, range: range3, scheme: scheme28, unknown, ...options }) {
  interval2 = maybeRangeInterval(interval2, type2);
  if (domain === void 0) domain = inferDomain2(channels, interval2, key);
  let hint;
  if (registry.get(key) === symbol) {
    hint = inferSymbolHint(channels);
    range3 = range3 === void 0 ? inferSymbolRange(hint) : map4(range3, maybeSymbol);
  } else if (registry.get(key) === color2) {
    if (range3 === void 0 && (type2 === "ordinal" || type2 === ordinalImplicit)) {
      range3 = maybeBooleanRange(domain, scheme28);
      if (range3 !== void 0) scheme28 = void 0;
    }
    if (scheme28 === void 0 && range3 === void 0) {
      scheme28 = type2 === "ordinal" ? "turbo" : "observable10";
    }
    if (scheme28 !== void 0) {
      if (range3 !== void 0) {
        const interpolate = quantitativeScheme(scheme28);
        const t03 = range3[0], d = range3[1] - range3[0];
        range3 = ({ length: n }) => quantize_default((t) => interpolate(t03 + d * t), n);
      } else {
        range3 = ordinalScheme(scheme28);
      }
    }
  }
  if (unknown === implicit) {
    throw new Error(`implicit unknown on ${key} scale is not supported`);
  }
  return createScaleO(key, ordinal().unknown(unknown), channels, { ...options, type: type2, domain, range: range3, hint });
}
function createScalePoint(key, channels, { align = 0.5, padding = 0.5, ...options }) {
  return maybeRound(point().align(align).padding(padding), channels, options, key);
}
function createScaleBand(key, channels, {
  align = 0.5,
  padding = 0.1,
  paddingInner = padding,
  paddingOuter = key === "fx" || key === "fy" ? 0 : padding,
  ...options
}) {
  return maybeRound(
    band().align(align).paddingInner(paddingInner).paddingOuter(paddingOuter),
    channels,
    options,
    key
  );
}
function maybeRound(scale3, channels, options, key) {
  let { round: round2 } = options;
  if (round2 !== void 0) scale3.round(round2 = !!round2);
  scale3 = createScaleO(key, scale3, channels, options);
  scale3.round = round2;
  return scale3;
}
function inferDomain2(channels, interval2, key) {
  const values2 = new InternSet();
  for (const { value, domain } of channels) {
    if (domain !== void 0) return domain();
    if (value === void 0) continue;
    for (const v2 of value) values2.add(v2);
  }
  if (interval2 !== void 0) {
    const [min4, max5] = extent(values2).map(interval2.floor, interval2);
    return interval2.range(min4, interval2.offset(max5));
  }
  if (values2.size > 1e4 && registry.get(key) === position) {
    throw new Error(`implicit ordinal domain of ${key} scale has more than 10,000 values`);
  }
  return sort(values2, ascendingDefined2);
}
function inferHint(channels, key) {
  let value;
  for (const { hint } of channels) {
    const candidate = hint == null ? void 0 : hint[key];
    if (candidate === void 0) continue;
    if (value === void 0) value = candidate;
    else if (value !== candidate) return;
  }
  return value;
}
function inferSymbolHint(channels) {
  return {
    fill: inferHint(channels, "fill"),
    stroke: inferHint(channels, "stroke")
  };
}
function inferSymbolRange(hint) {
  return isNoneish(hint.fill) ? symbolsStroke : symbolsFill;
}

// node_modules/@observablehq/plot/src/scales.js
function createScales(channelsByScale, {
  label: globalLabel,
  inset: globalInset = 0,
  insetTop: globalInsetTop = globalInset,
  insetRight: globalInsetRight = globalInset,
  insetBottom: globalInsetBottom = globalInset,
  insetLeft: globalInsetLeft = globalInset,
  round: round2,
  nice: nice3,
  clamp,
  zero: zero3,
  align,
  padding,
  projection: projection3,
  facet: { label: facetLabel = globalLabel } = {},
  ...options
} = {}) {
  const scales = {};
  for (const [key, channels] of channelsByScale) {
    const scaleOptions = options[key];
    const scale3 = createScale(key, channels, {
      round: registry.get(key) === position ? round2 : void 0,
      // only for position
      nice: nice3,
      clamp,
      zero: zero3,
      align,
      padding,
      projection: projection3,
      ...scaleOptions
    });
    if (scale3) {
      let {
        label = key === "fx" || key === "fy" ? facetLabel : globalLabel,
        percent,
        transform: transform2,
        inset,
        insetTop = inset !== void 0 ? inset : key === "y" ? globalInsetTop : 0,
        // not fy
        insetRight = inset !== void 0 ? inset : key === "x" ? globalInsetRight : 0,
        // not fx
        insetBottom = inset !== void 0 ? inset : key === "y" ? globalInsetBottom : 0,
        // not fy
        insetLeft = inset !== void 0 ? inset : key === "x" ? globalInsetLeft : 0
        // not fx
      } = scaleOptions || {};
      if (transform2 == null) transform2 = void 0;
      else if (typeof transform2 !== "function") throw new Error("invalid scale transform; not a function");
      scale3.percent = !!percent;
      scale3.label = label === void 0 ? inferScaleLabel(channels, scale3) : label;
      scale3.transform = transform2;
      if (key === "x" || key === "fx") {
        scale3.insetLeft = +insetLeft;
        scale3.insetRight = +insetRight;
      } else if (key === "y" || key === "fy") {
        scale3.insetTop = +insetTop;
        scale3.insetBottom = +insetBottom;
      }
      scales[key] = scale3;
    }
  }
  return scales;
}
function createScaleFunctions(descriptors) {
  const scales = {};
  const scaleFunctions = { scales };
  for (const [key, descriptor] of Object.entries(descriptors)) {
    const { scale: scale3, type: type2, interval: interval2, label } = descriptor;
    scales[key] = exposeScale(descriptor);
    scaleFunctions[key] = scale3;
    scale3.type = type2;
    if (interval2 != null) scale3.interval = interval2;
    if (label != null) scale3.label = label;
  }
  return scaleFunctions;
}
function autoScaleRange(scales, dimensions) {
  const { x: x3, y: y3, fx, fy } = scales;
  const superdimensions = fx || fy ? outerDimensions(dimensions) : dimensions;
  if (fx) autoScaleRangeX(fx, superdimensions);
  if (fy) autoScaleRangeY(fy, superdimensions);
  const subdimensions = fx || fy ? innerDimensions(scales, dimensions) : dimensions;
  if (x3) autoScaleRangeX(x3, subdimensions);
  if (y3) autoScaleRangeY(y3, subdimensions);
}
function inferScaleLabel(channels = [], scale3) {
  let label;
  for (const { label: l } of channels) {
    if (l === void 0) continue;
    if (label === void 0) label = l;
    else if (label !== l) return;
  }
  if (label === void 0) return;
  if (!isOrdinalScale(scale3) && scale3.percent) label = `${label} (%)`;
  return { inferred: true, toString: () => label };
}
function inferScaleOrder(scale3) {
  return Math.sign(orderof(scale3.domain())) * Math.sign(orderof(scale3.range()));
}
function outerDimensions(dimensions) {
  const {
    marginTop,
    marginRight,
    marginBottom,
    marginLeft,
    width,
    height,
    facet: {
      marginTop: facetMarginTop,
      marginRight: facetMarginRight,
      marginBottom: facetMarginBottom,
      marginLeft: facetMarginLeft
    }
  } = dimensions;
  return {
    marginTop: Math.max(marginTop, facetMarginTop),
    marginRight: Math.max(marginRight, facetMarginRight),
    marginBottom: Math.max(marginBottom, facetMarginBottom),
    marginLeft: Math.max(marginLeft, facetMarginLeft),
    width,
    height
  };
}
function innerDimensions({ fx, fy }, dimensions) {
  const { marginTop, marginRight, marginBottom, marginLeft, width, height } = outerDimensions(dimensions);
  return {
    marginTop,
    marginRight,
    marginBottom,
    marginLeft,
    width: fx ? fx.scale.bandwidth() + marginLeft + marginRight : width,
    height: fy ? fy.scale.bandwidth() + marginTop + marginBottom : height,
    facet: { width, height }
  };
}
function autoScaleRangeX(scale3, dimensions) {
  if (scale3.range === void 0) {
    const { insetLeft, insetRight } = scale3;
    const { width, marginLeft = 0, marginRight = 0 } = dimensions;
    const left2 = marginLeft + insetLeft;
    const right2 = width - marginRight - insetRight;
    scale3.range = [left2, Math.max(left2, right2)];
    if (!isOrdinalScale(scale3)) scale3.range = piecewiseRange(scale3);
    scale3.scale.range(scale3.range);
  }
  autoScaleRound(scale3);
}
function autoScaleRangeY(scale3, dimensions) {
  if (scale3.range === void 0) {
    const { insetTop, insetBottom } = scale3;
    const { height, marginTop = 0, marginBottom = 0 } = dimensions;
    const top2 = marginTop + insetTop;
    const bottom2 = height - marginBottom - insetBottom;
    scale3.range = [Math.max(top2, bottom2), top2];
    if (!isOrdinalScale(scale3)) scale3.range = piecewiseRange(scale3);
    else scale3.range.reverse();
    scale3.scale.range(scale3.range);
  }
  autoScaleRound(scale3);
}
function autoScaleRound(scale3) {
  if (scale3.round === void 0 && isBandScale(scale3) && roundError(scale3) <= 30) {
    scale3.scale.round(true);
  }
}
function roundError({ scale: scale3 }) {
  const n = scale3.domain().length;
  const [start2, stop] = scale3.range();
  const paddingInner = scale3.paddingInner ? scale3.paddingInner() : 1;
  const paddingOuter = scale3.paddingOuter ? scale3.paddingOuter() : scale3.padding();
  const m = n - paddingInner;
  const step = Math.abs(stop - start2) / Math.max(1, m + paddingOuter * 2);
  return (step - Math.floor(step)) * m;
}
function piecewiseRange(scale3) {
  const length3 = scale3.scale.domain().length + isThresholdScale(scale3);
  if (!(length3 > 2)) return scale3.range;
  const [start2, end] = scale3.range;
  return Array.from({ length: length3 }, (_, i) => start2 + i / (length3 - 1) * (end - start2));
}
function normalizeScale(key, scale3, hint) {
  return createScale(key, hint === void 0 ? void 0 : [{ hint }], { ...scale3 });
}
function createScale(key, channels = [], options = {}) {
  const type2 = inferScaleType(key, channels, options);
  if (options.type === void 0 && options.domain === void 0 && options.range === void 0 && options.interval == null && key !== "fx" && key !== "fy" && isOrdinalScale({ type: type2 })) {
    const values2 = channels.map(({ value }) => value).filter((value) => value !== void 0);
    if (values2.some(isTemporal))
      warn(
        `Warning: some data associated with the ${key} scale are dates. Dates are typically associated with a "utc" or "time" scale rather than a "${formatScaleType(
          type2
        )}" scale. If you are using a bar mark, you probably want a rect mark with the interval option instead; if you are using a group transform, you probably want a bin transform instead. If you want to treat this data as ordinal, you can specify the interval of the ${key} scale (e.g., d3.utcDay), or you can suppress this warning by setting the type of the ${key} scale to "${formatScaleType(
          type2
        )}".`
      );
    else if (values2.some(isTemporalString))
      warn(
        `Warning: some data associated with the ${key} scale are strings that appear to be dates (e.g., YYYY-MM-DD). If these strings represent dates, you should parse them to Date objects. Dates are typically associated with a "utc" or "time" scale rather than a "${formatScaleType(
          type2
        )}" scale. If you are using a bar mark, you probably want a rect mark with the interval option instead; if you are using a group transform, you probably want a bin transform instead. If you want to treat this data as ordinal, you can suppress this warning by setting the type of the ${key} scale to "${formatScaleType(
          type2
        )}".`
      );
    else if (values2.some(isNumericString))
      warn(
        `Warning: some data associated with the ${key} scale are strings that appear to be numbers. If these strings represent numbers, you should parse or coerce them to numbers. Numbers are typically associated with a "linear" scale rather than a "${formatScaleType(
          type2
        )}" scale. If you want to treat this data as ordinal, you can specify the interval of the ${key} scale (e.g., 1 for integers), or you can suppress this warning by setting the type of the ${key} scale to "${formatScaleType(
          type2
        )}".`
      );
  }
  options.type = type2;
  switch (type2) {
    case "diverging":
    case "diverging-sqrt":
    case "diverging-pow":
    case "diverging-log":
    case "diverging-symlog":
    case "cyclical":
    case "sequential":
    case "linear":
    case "sqrt":
    case "threshold":
    case "quantile":
    case "pow":
    case "log":
    case "symlog":
      options = coerceType(channels, options, coerceNumbers);
      break;
    case "identity":
      switch (registry.get(key)) {
        case position:
          options = coerceType(channels, options, coerceNumbers);
          break;
        case symbol:
          options = coerceType(channels, options, coerceSymbols);
          break;
      }
      break;
    case "utc":
    case "time":
      options = coerceType(channels, options, coerceDates);
      break;
  }
  switch (type2) {
    case "diverging":
      return createScaleDiverging(key, channels, options);
    case "diverging-sqrt":
      return createScaleDivergingSqrt(key, channels, options);
    case "diverging-pow":
      return createScaleDivergingPow(key, channels, options);
    case "diverging-log":
      return createScaleDivergingLog(key, channels, options);
    case "diverging-symlog":
      return createScaleDivergingSymlog(key, channels, options);
    case "categorical":
    case "ordinal":
    case ordinalImplicit:
      return createScaleOrdinal(key, channels, options);
    case "cyclical":
    case "sequential":
    case "linear":
      return createScaleLinear(key, channels, options);
    case "sqrt":
      return createScaleSqrt(key, channels, options);
    case "threshold":
      return createScaleThreshold(key, channels, options);
    case "quantile":
      return createScaleQuantile(key, channels, options);
    case "quantize":
      return createScaleQuantize(key, channels, options);
    case "pow":
      return createScalePow(key, channels, options);
    case "log":
      return createScaleLog(key, channels, options);
    case "symlog":
      return createScaleSymlog(key, channels, options);
    case "utc":
      return createScaleUtc(key, channels, options);
    case "time":
      return createScaleTime(key, channels, options);
    case "point":
      return createScalePoint(key, channels, options);
    case "band":
      return createScaleBand(key, channels, options);
    case "identity":
      return createScaleIdentity(key);
    case void 0:
      return;
    default:
      throw new Error(`unknown scale type: ${type2}`);
  }
}
function formatScaleType(type2) {
  return typeof type2 === "symbol" ? type2.description : type2;
}
function maybeScaleType(type2) {
  return typeof type2 === "string" ? `${type2}`.toLowerCase() : type2;
}
var typeProjection = { toString: () => "projection" };
function inferScaleType(key, channels, { type: type2, domain, range: range3, scheme: scheme28, pivot, projection: projection3 }) {
  var _a;
  type2 = maybeScaleType(type2);
  if (key === "fx" || key === "fy") return "band";
  if ((key === "x" || key === "y") && projection3 != null) type2 = typeProjection;
  for (const channel of channels) {
    const t = maybeScaleType(channel.type);
    if (t === void 0) continue;
    else if (type2 === void 0) type2 = t;
    else if (type2 !== t) throw new Error(`scale incompatible with channel: ${type2} !== ${t}`);
  }
  if (type2 === typeProjection) return;
  if (type2 !== void 0) return type2;
  if (domain === void 0 && !channels.some(({ value }) => value !== void 0)) return;
  const kind = registry.get(key);
  if (kind === radius) return "sqrt";
  if (kind === opacity || kind === length2) return "linear";
  if (kind === symbol) return "ordinal";
  const n = (_a = domain ?? range3) == null ? void 0 : _a.length;
  if (n < 2 || n > 2) return asOrdinalType(kind);
  if (domain !== void 0) {
    if (isOrdinal(domain)) return asOrdinalType(kind);
    if (isTemporal(domain)) return "utc";
  } else {
    const values2 = channels.map(({ value }) => value).filter((value) => value !== void 0);
    if (values2.some(isOrdinal)) return asOrdinalType(kind);
    if (values2.some(isTemporal)) return "utc";
  }
  if (kind === color2) {
    if (pivot != null || isDivergingScheme(scheme28)) return "diverging";
    if (isCategoricalScheme(scheme28)) return "categorical";
  }
  return "linear";
}
function asOrdinalType(kind) {
  switch (kind) {
    case position:
      return "point";
    case color2:
      return ordinalImplicit;
    default:
      return "ordinal";
  }
}
function isOrdinalScale({ type: type2 }) {
  return type2 === "ordinal" || type2 === "point" || type2 === "band" || type2 === ordinalImplicit;
}
function isThresholdScale({ type: type2 }) {
  return type2 === "threshold";
}
function isBandScale({ type: type2 }) {
  return type2 === "point" || type2 === "band";
}
function isCollapsed(scale3) {
  if (scale3 === void 0) return true;
  const domain = scale3.domain();
  const value = scale3(domain[0]);
  for (let i = 1, n = domain.length; i < n; ++i) {
    if (scale3(domain[i]) - value) {
      return false;
    }
  }
  return true;
}
function coerceType(channels, { domain, ...options }, coerceValues) {
  var _a;
  for (const c4 of channels) {
    if (c4.value !== void 0) {
      if (domain === void 0) domain = (_a = c4.value) == null ? void 0 : _a.domain;
      c4.value = coerceValues(c4.value);
    }
  }
  return {
    domain: domain === void 0 ? domain : coerceValues(domain),
    ...options
  };
}
function coerceSymbols(values2) {
  return map4(values2, maybeSymbol);
}
function scale2(options = {}) {
  let scale3;
  for (const key in options) {
    if (!registry.has(key)) continue;
    if (!isScaleOptions(options[key])) continue;
    if (scale3 !== void 0) throw new Error("ambiguous scale definition; multiple scales found");
    scale3 = exposeScale(normalizeScale(key, options[key]));
  }
  if (scale3 === void 0) throw new Error("invalid scale definition; no scale found");
  return scale3;
}
function exposeScales(scales) {
  return (key) => {
    if (!registry.has(key = `${key}`)) throw new Error(`unknown scale: ${key}`);
    return scales[key];
  };
}
function exposeScale({ scale: scale3, type: type2, domain, range: range3, interpolate, interval: interval2, transform: transform2, percent, pivot }) {
  if (type2 === "identity") return { type: "identity", apply: (d) => d, invert: (d) => d };
  const unknown = scale3.unknown ? scale3.unknown() : void 0;
  return {
    type: type2,
    domain: slice5(domain),
    // defensive copy
    ...range3 !== void 0 && { range: slice5(range3) },
    // defensive copy
    ...transform2 !== void 0 && { transform: transform2 },
    ...percent && { percent },
    // only exposed if truthy
    ...unknown !== void 0 && { unknown },
    ...interval2 !== void 0 && { interval: interval2 },
    // quantitative
    ...interpolate !== void 0 && { interpolate },
    ...scale3.clamp && { clamp: scale3.clamp() },
    // diverging (always asymmetric; we never want to apply the symmetric transform twice)
    ...pivot !== void 0 && { pivot, symmetric: false },
    // log, diverging-log
    ...scale3.base && { base: scale3.base() },
    // pow, diverging-pow
    ...scale3.exponent && { exponent: scale3.exponent() },
    // symlog, diverging-symlog
    ...scale3.constant && { constant: scale3.constant() },
    // band, point
    ...scale3.align && { align: scale3.align(), round: scale3.round() },
    ...scale3.padding && (scale3.paddingInner ? { paddingInner: scale3.paddingInner(), paddingOuter: scale3.paddingOuter() } : { padding: scale3.padding() }),
    ...scale3.bandwidth && { bandwidth: scale3.bandwidth(), step: scale3.step() },
    // utilities
    apply: (t) => scale3(t),
    ...scale3.invert && { invert: (t) => scale3.invert(t) }
  };
}

// node_modules/@observablehq/plot/src/facet.js
function createFacets(channelsByScale, options) {
  const { fx, fy } = createScales(channelsByScale, options);
  const fxDomain = fx == null ? void 0 : fx.scale.domain();
  const fyDomain = fy == null ? void 0 : fy.scale.domain();
  return fxDomain && fyDomain ? cross(fxDomain, fyDomain).map(([x3, y3], i) => ({ x: x3, y: y3, i })) : fxDomain ? fxDomain.map((x3, i) => ({ x: x3, i })) : fyDomain ? fyDomain.map((y3, i) => ({ y: y3, i })) : void 0;
}
function recreateFacets(facets, { x: X3, y: Y3 }) {
  X3 && (X3 = facetIndex(X3));
  Y3 && (Y3 = facetIndex(Y3));
  return facets.filter(
    X3 && Y3 ? (f) => X3.has(f.x) && Y3.has(f.y) : X3 ? (f) => X3.has(f.x) : (f) => Y3.has(f.y)
  ).sort(
    X3 && Y3 ? (a2, b) => X3.get(a2.x) - X3.get(b.x) || Y3.get(a2.y) - Y3.get(b.y) : X3 ? (a2, b) => X3.get(a2.x) - X3.get(b.x) : (a2, b) => Y3.get(a2.y) - Y3.get(b.y)
  );
}
function facetGroups(data, { fx, fy }) {
  const I = range2(data);
  const FX = fx == null ? void 0 : fx.value;
  const FY = fy == null ? void 0 : fy.value;
  return fx && fy ? rollup(
    I,
    (G) => (G.fx = FX[G[0]], G.fy = FY[G[0]], G),
    (i) => FX[i],
    (i) => FY[i]
  ) : fx ? rollup(
    I,
    (G) => (G.fx = FX[G[0]], G),
    (i) => FX[i]
  ) : rollup(
    I,
    (G) => (G.fy = FY[G[0]], G),
    (i) => FY[i]
  );
}
function facetTranslator(fx, fy, { marginTop, marginLeft }) {
  const x3 = fx ? ({ x: x4 }) => fx(x4) - marginLeft : () => 0;
  const y3 = fy ? ({ y: y4 }) => fy(y4) - marginTop : () => 0;
  return function(d) {
    if (this.tagName === "svg") {
      this.setAttribute("x", x3(d));
      this.setAttribute("y", y3(d));
    } else {
      this.setAttribute("transform", `translate(${x3(d)},${y3(d)})`);
    }
  };
}
function facetExclude(index2) {
  const ex = [];
  const e = new Uint32Array(sum(index2, (d) => d.length));
  for (const i of index2) {
    let n = 0;
    for (const j of index2) {
      if (i === j) continue;
      e.set(j, n);
      n += j.length;
    }
    ex.push(e.slice(0, n));
  }
  return ex;
}
var facetAnchors = /* @__PURE__ */ new Map([
  ["top", facetAnchorTop],
  ["right", facetAnchorRight],
  ["bottom", facetAnchorBottom],
  ["left", facetAnchorLeft],
  ["top-left", and(facetAnchorTop, facetAnchorLeft)],
  ["top-right", and(facetAnchorTop, facetAnchorRight)],
  ["bottom-left", and(facetAnchorBottom, facetAnchorLeft)],
  ["bottom-right", and(facetAnchorBottom, facetAnchorRight)],
  ["top-empty", facetAnchorTopEmpty],
  ["right-empty", facetAnchorRightEmpty],
  ["bottom-empty", facetAnchorBottomEmpty],
  ["left-empty", facetAnchorLeftEmpty],
  ["empty", facetAnchorEmpty]
]);
function maybeFacetAnchor(facetAnchor) {
  if (facetAnchor == null) return null;
  const anchor = facetAnchors.get(`${facetAnchor}`.toLowerCase());
  if (anchor) return anchor;
  throw new Error(`invalid facet anchor: ${facetAnchor}`);
}
var indexCache = /* @__PURE__ */ new WeakMap();
function facetIndex(V) {
  let I = indexCache.get(V);
  if (!I) indexCache.set(V, I = new InternMap(map4(V, (v2, i) => [v2, i])));
  return I;
}
function facetIndexOf(V, v2) {
  return facetIndex(V).get(v2);
}
function facetFind(facets, x3, y3) {
  x3 = keyof2(x3);
  y3 = keyof2(y3);
  return facets.find((f) => Object.is(keyof2(f.x), x3) && Object.is(keyof2(f.y), y3));
}
function facetEmpty(facets, x3, y3) {
  var _a;
  return (_a = facetFind(facets, x3, y3)) == null ? void 0 : _a.empty;
}
function facetAnchorTop(facets, { y: Y3 }, { y: y3 }) {
  return Y3 ? facetIndexOf(Y3, y3) === 0 : true;
}
function facetAnchorBottom(facets, { y: Y3 }, { y: y3 }) {
  return Y3 ? facetIndexOf(Y3, y3) === Y3.length - 1 : true;
}
function facetAnchorLeft(facets, { x: X3 }, { x: x3 }) {
  return X3 ? facetIndexOf(X3, x3) === 0 : true;
}
function facetAnchorRight(facets, { x: X3 }, { x: x3 }) {
  return X3 ? facetIndexOf(X3, x3) === X3.length - 1 : true;
}
function facetAnchorTopEmpty(facets, { y: Y3 }, { x: x3, y: y3, empty: empty3 }) {
  if (empty3) return false;
  if (!Y3) return;
  const i = facetIndexOf(Y3, y3);
  if (i > 0) return facetEmpty(facets, x3, Y3[i - 1]);
}
function facetAnchorBottomEmpty(facets, { y: Y3 }, { x: x3, y: y3, empty: empty3 }) {
  if (empty3) return false;
  if (!Y3) return;
  const i = facetIndexOf(Y3, y3);
  if (i < Y3.length - 1) return facetEmpty(facets, x3, Y3[i + 1]);
}
function facetAnchorLeftEmpty(facets, { x: X3 }, { x: x3, y: y3, empty: empty3 }) {
  if (empty3) return false;
  if (!X3) return;
  const i = facetIndexOf(X3, x3);
  if (i > 0) return facetEmpty(facets, X3[i - 1], y3);
}
function facetAnchorRightEmpty(facets, { x: X3 }, { x: x3, y: y3, empty: empty3 }) {
  if (empty3) return false;
  if (!X3) return;
  const i = facetIndexOf(X3, x3);
  if (i < X3.length - 1) return facetEmpty(facets, X3[i + 1], y3);
}
function facetAnchorEmpty(facets, channels, { empty: empty3 }) {
  return empty3;
}
function and(a2, b) {
  return function() {
    return a2.apply(null, arguments) && b.apply(null, arguments);
  };
}
function facetFilter(facets, { channels: { fx, fy }, groups: groups2 }) {
  return fx && fy ? facets.map(({ x: x3, y: y3 }) => {
    var _a;
    return ((_a = groups2.get(x3)) == null ? void 0 : _a.get(y3)) ?? [];
  }) : fx ? facets.map(({ x: x3 }) => groups2.get(x3) ?? []) : facets.map(({ y: y3 }) => groups2.get(y3) ?? []);
}

// node_modules/@observablehq/plot/src/projection.js
var pi6 = Math.PI;
var tau7 = 2 * pi6;
var defaultAspectRatio = 0.618;
function createProjection({
  projection: projection3,
  inset: globalInset = 0,
  insetTop = globalInset,
  insetRight = globalInset,
  insetBottom = globalInset,
  insetLeft = globalInset
} = {}, dimensions) {
  if (projection3 == null) return;
  if (typeof projection3.stream === "function") return projection3;
  let options;
  let domain;
  let clip = "frame";
  if (isObject(projection3)) {
    let inset;
    ({
      type: projection3,
      domain,
      inset,
      insetTop = inset !== void 0 ? inset : insetTop,
      insetRight = inset !== void 0 ? inset : insetRight,
      insetBottom = inset !== void 0 ? inset : insetBottom,
      insetLeft = inset !== void 0 ? inset : insetLeft,
      clip = clip,
      ...options
    } = projection3);
    if (projection3 == null) return;
  }
  if (typeof projection3 !== "function") ({ type: projection3 } = namedProjection(projection3));
  const { width, height, marginLeft, marginRight, marginTop, marginBottom } = dimensions;
  const dx = width - marginLeft - marginRight - insetLeft - insetRight;
  const dy = height - marginTop - marginBottom - insetTop - insetBottom;
  projection3 = projection3 == null ? void 0 : projection3({ width: dx, height: dy, clip, ...options });
  if (projection3 == null) return;
  clip = maybePostClip(clip, marginLeft, marginTop, width - marginRight, height - marginBottom);
  let tx = marginLeft + insetLeft;
  let ty = marginTop + insetTop;
  let transform2;
  if (domain != null) {
    const [[x06, y06], [x12, y12]] = path_default(projection3).bounds(domain);
    const k2 = Math.min(dx / (x12 - x06), dy / (y12 - y06));
    if (k2 > 0) {
      tx -= (k2 * (x06 + x12) - dx) / 2;
      ty -= (k2 * (y06 + y12) - dy) / 2;
      transform2 = transform_default({
        point(x3, y3) {
          this.stream.point(x3 * k2 + tx, y3 * k2 + ty);
        }
      });
    } else {
      warn(`Warning: the projection could not be fit to the specified domain; using the default scale.`);
    }
  }
  transform2 ?? (transform2 = tx === 0 && ty === 0 ? identity7() : transform_default({
    point(x3, y3) {
      this.stream.point(x3 + tx, y3 + ty);
    }
  }));
  return { stream: (s2) => projection3.stream(transform2.stream(clip(s2))) };
}
function namedProjection(projection3) {
  switch (`${projection3}`.toLowerCase()) {
    case "albers-usa":
      return scaleProjection(albersUsa_default, 0.7463, 0.4673);
    case "albers":
      return conicProjection2(albers_default, 0.7463, 0.4673);
    case "azimuthal-equal-area":
      return scaleProjection(azimuthalEqualArea_default, 4, 4);
    case "azimuthal-equidistant":
      return scaleProjection(azimuthalEquidistant_default, tau7, tau7);
    case "conic-conformal":
      return conicProjection2(conicConformal_default, tau7, tau7);
    case "conic-equal-area":
      return conicProjection2(conicEqualArea_default, 6.1702, 2.9781);
    case "conic-equidistant":
      return conicProjection2(conicEquidistant_default, 7.312, 3.6282);
    case "equal-earth":
      return scaleProjection(equalEarth_default, 5.4133, 2.6347);
    case "equirectangular":
      return scaleProjection(equirectangular_default, tau7, pi6);
    case "gnomonic":
      return scaleProjection(gnomonic_default, 3.4641, 3.4641);
    case "identity":
      return { type: identity7 };
    case "reflect-y":
      return { type: reflectY };
    case "mercator":
      return scaleProjection(mercator_default, tau7, tau7);
    case "orthographic":
      return scaleProjection(orthographic_default, 2, 2);
    case "stereographic":
      return scaleProjection(stereographic_default, 2, 2);
    case "transverse-mercator":
      return scaleProjection(transverseMercator_default, tau7, tau7);
    default:
      throw new Error(`unknown projection type: ${projection3}`);
  }
}
function maybePostClip(clip, x12, y12, x22, y22) {
  if (clip === false || clip == null || typeof clip === "number") return (s2) => s2;
  if (clip === true) clip = "frame";
  switch (`${clip}`.toLowerCase()) {
    case "frame":
      return clipRectangle(x12, y12, x22, y22);
    default:
      throw new Error(`unknown projection clip type: ${clip}`);
  }
}
function scaleProjection(createProjection2, kx2, ky2) {
  return {
    type: ({ width, height, rotate, precision = 0.15, clip }) => {
      var _a, _b, _c;
      const projection3 = createProjection2();
      if (precision != null) (_a = projection3.precision) == null ? void 0 : _a.call(projection3, precision);
      if (rotate != null) (_b = projection3.rotate) == null ? void 0 : _b.call(projection3, rotate);
      if (typeof clip === "number") (_c = projection3.clipAngle) == null ? void 0 : _c.call(projection3, clip);
      if (width != null) {
        projection3.scale(Math.min(width / kx2, height / ky2));
        projection3.translate([width / 2, height / 2]);
      }
      return projection3;
    },
    aspectRatio: ky2 / kx2
  };
}
function conicProjection2(createProjection2, kx2, ky2) {
  const { type: type2, aspectRatio } = scaleProjection(createProjection2, kx2, ky2);
  return {
    type: (options) => {
      const { parallels, domain, width, height } = options;
      const projection3 = type2(options);
      if (parallels != null) {
        projection3.parallels(parallels);
        if (domain === void 0 && width != null) {
          projection3.fitSize([width, height], { type: "Sphere" });
        }
      }
      return projection3;
    },
    aspectRatio
  };
}
var identity7 = constant2({ stream: (stream) => stream });
var reflectY = constant2(
  transform_default({
    point(x3, y3) {
      this.stream.point(x3, -y3);
    }
  })
);
function project(cx, cy, values2, projection3) {
  const x3 = values2[cx];
  const y3 = values2[cy];
  const n = x3.length;
  const X3 = values2[cx] = new Float64Array(n).fill(NaN);
  const Y3 = values2[cy] = new Float64Array(n).fill(NaN);
  let i;
  const stream = projection3.stream({
    point(x4, y4) {
      X3[i] = x4;
      Y3[i] = y4;
    }
  });
  for (i = 0; i < n; ++i) {
    stream.point(x3[i], y3[i]);
  }
}
function hasProjection({ projection: projection3 } = {}) {
  if (projection3 == null) return false;
  if (typeof projection3.stream === "function") return true;
  if (isObject(projection3)) projection3 = projection3.type;
  return projection3 != null;
}
function projectionAspectRatio(projection3) {
  if (typeof (projection3 == null ? void 0 : projection3.stream) === "function") return defaultAspectRatio;
  if (isObject(projection3)) {
    let domain, options;
    ({ domain, type: projection3, ...options } = projection3);
    if (domain != null && projection3 != null) {
      const type2 = typeof projection3 === "string" ? namedProjection(projection3).type : projection3;
      const [[x06, y06], [x12, y12]] = path_default(type2({ ...options, width: 100, height: 100 })).bounds(domain);
      const r = (y12 - y06) / (x12 - x06);
      return r && isFinite(r) ? r < 0.2 ? 0.2 : r > 5 ? 5 : r : defaultAspectRatio;
    }
  }
  if (projection3 == null) return;
  if (typeof projection3 !== "function") {
    const { aspectRatio } = namedProjection(projection3);
    if (aspectRatio) return aspectRatio;
  }
  return defaultAspectRatio;
}
function applyPosition(channels, scales, { projection: projection3 }) {
  const { x: x3, y: y3 } = channels;
  let position3 = {};
  if (x3) position3.x = x3;
  if (y3) position3.y = y3;
  position3 = valueObject(position3, scales);
  if (projection3 && (x3 == null ? void 0 : x3.scale) === "x" && (y3 == null ? void 0 : y3.scale) === "y") project("x", "y", position3, projection3);
  if (x3) position3.x = coerceNumbers(position3.x);
  if (y3) position3.y = coerceNumbers(position3.y);
  return position3;
}
function getGeometryChannels(channel) {
  const X3 = [];
  const Y3 = [];
  const x3 = { scale: "x", value: X3 };
  const y3 = { scale: "y", value: Y3 };
  const sink = {
    point(x4, y4) {
      X3.push(x4);
      Y3.push(y4);
    },
    lineStart() {
    },
    lineEnd() {
    },
    polygonStart() {
    },
    polygonEnd() {
    },
    sphere() {
    }
  };
  for (const object of channel.value) stream_default(object, sink);
  return [x3, y3];
}
function xyProjection({ x: X3, y: Y3 }) {
  if (X3 || Y3) {
    X3 ?? (X3 = (x3) => x3);
    Y3 ?? (Y3 = (y3) => y3);
    return transform_default({
      point(x3, y3) {
        this.stream.point(X3(x3), Y3(y3));
      }
    });
  }
}

// node_modules/@observablehq/plot/src/context.js
function createContext(options = {}) {
  const { document: document2 = typeof window !== "undefined" ? window.document : void 0, clip } = options;
  return { document: document2, clip: maybeClip(clip) };
}
function create2(name, { document: document2 }) {
  return select_default2(creator_default(name).call(document2.documentElement));
}

// node_modules/@observablehq/plot/src/memoize.js
var unset = Symbol("unset");
function memoize1(compute) {
  return (compute.length === 1 ? memoize1Arg : memoize1Args)(compute);
}
function memoize1Arg(compute) {
  let cacheValue;
  let cacheKey = unset;
  return (key) => {
    if (!Object.is(cacheKey, key)) {
      cacheKey = key;
      cacheValue = compute(key);
    }
    return cacheValue;
  };
}
function memoize1Args(compute) {
  let cacheValue, cacheKeys;
  return (...keys) => {
    if ((cacheKeys == null ? void 0 : cacheKeys.length) !== keys.length || cacheKeys.some((k2, i) => !Object.is(k2, keys[i]))) {
      cacheKeys = keys;
      cacheValue = compute(...keys);
    }
    return cacheValue;
  };
}

// node_modules/@observablehq/plot/src/format.js
var numberFormat = memoize1((locale3) => {
  return new Intl.NumberFormat(locale3);
});
var monthFormat = memoize1((locale3, month) => {
  return new Intl.DateTimeFormat(locale3, { timeZone: "UTC", ...month && { month } });
});
var weekdayFormat = memoize1((locale3, weekday) => {
  return new Intl.DateTimeFormat(locale3, { timeZone: "UTC", ...weekday && { weekday } });
});
function formatNumber(locale3 = "en-US") {
  const format3 = numberFormat(locale3);
  return (i) => i != null && !isNaN(i) ? format3.format(i) : void 0;
}
function formatMonth(locale3 = "en-US", format3 = "short") {
  const fmt = monthFormat(locale3, format3);
  return (i) => i != null && !isNaN(i = +new Date(Date.UTC(2e3, +i))) ? fmt.format(i) : void 0;
}
function formatWeekday(locale3 = "en-US", format3 = "short") {
  const fmt = weekdayFormat(locale3, format3);
  return (i) => i != null && !isNaN(i = +new Date(Date.UTC(2001, 0, +i))) ? fmt.format(i) : void 0;
}
function formatIsoDate(date2) {
  return format2(date2, "Invalid Date");
}
function formatAuto(locale3 = "en-US") {
  const number7 = formatNumber(locale3);
  return (v2) => (v2 instanceof Date ? formatIsoDate : typeof v2 === "number" ? number7 : string)(v2);
}
var formatDefault = formatAuto();

// node_modules/@observablehq/plot/src/style.js
var offset = (typeof window !== "undefined" ? window.devicePixelRatio > 1 : typeof it === "undefined") ? 0 : 0.5;
var nextClipId = 0;
var nextPatternId = 0;
function getClipId() {
  return `plot-clip-${++nextClipId}`;
}
function getPatternId() {
  return `plot-pattern-${++nextPatternId}`;
}
function styles(mark, {
  title,
  href,
  ariaLabel: variaLabel,
  ariaDescription,
  ariaHidden,
  target,
  fill,
  fillOpacity,
  stroke,
  strokeWidth,
  strokeOpacity,
  strokeLinejoin,
  strokeLinecap,
  strokeMiterlimit,
  strokeDasharray,
  strokeDashoffset,
  opacity: opacity2,
  mixBlendMode,
  imageFilter,
  paintOrder,
  pointerEvents,
  shapeRendering,
  channels
}, {
  ariaLabel: cariaLabel,
  fill: defaultFill = "currentColor",
  fillOpacity: defaultFillOpacity,
  stroke: defaultStroke = "none",
  strokeOpacity: defaultStrokeOpacity,
  strokeWidth: defaultStrokeWidth,
  strokeLinecap: defaultStrokeLinecap,
  strokeLinejoin: defaultStrokeLinejoin,
  strokeMiterlimit: defaultStrokeMiterlimit,
  paintOrder: defaultPaintOrder
}) {
  if (defaultFill === null) {
    fill = null;
    fillOpacity = null;
  }
  if (defaultStroke === null) {
    stroke = null;
    strokeOpacity = null;
  }
  if (isNoneish(defaultFill)) {
    if (!isNoneish(defaultStroke) && (!isNoneish(fill) || (channels == null ? void 0 : channels.fill))) defaultStroke = "none";
  } else {
    if (isNoneish(defaultStroke) && (!isNoneish(stroke) || (channels == null ? void 0 : channels.stroke))) defaultFill = "none";
  }
  const [vfill, cfill] = maybeColorChannel(fill, defaultFill);
  const [vfillOpacity, cfillOpacity] = maybeNumberChannel(fillOpacity, defaultFillOpacity);
  const [vstroke, cstroke] = maybeColorChannel(stroke, defaultStroke);
  const [vstrokeOpacity, cstrokeOpacity] = maybeNumberChannel(strokeOpacity, defaultStrokeOpacity);
  const [vopacity, copacity] = maybeNumberChannel(opacity2);
  if (!isNone(cstroke)) {
    if (strokeWidth === void 0) strokeWidth = defaultStrokeWidth;
    if (strokeLinecap === void 0) strokeLinecap = defaultStrokeLinecap;
    if (strokeLinejoin === void 0) strokeLinejoin = defaultStrokeLinejoin;
    if (strokeMiterlimit === void 0 && !isRound(strokeLinejoin)) strokeMiterlimit = defaultStrokeMiterlimit;
    if (!isNone(cfill) && paintOrder === void 0) paintOrder = defaultPaintOrder;
  }
  const [vstrokeWidth, cstrokeWidth] = maybeNumberChannel(strokeWidth);
  if (defaultFill !== null) {
    mark.fill = impliedString(cfill, "currentColor");
    mark.fillOpacity = impliedNumber(cfillOpacity, 1);
  }
  if (defaultStroke !== null) {
    mark.stroke = impliedString(cstroke, "none");
    mark.strokeWidth = impliedNumber(cstrokeWidth, 1);
    mark.strokeOpacity = impliedNumber(cstrokeOpacity, 1);
    mark.strokeLinejoin = impliedString(strokeLinejoin, "miter");
    mark.strokeLinecap = impliedString(strokeLinecap, "butt");
    mark.strokeMiterlimit = impliedNumber(strokeMiterlimit, 4);
    mark.strokeDasharray = impliedString(strokeDasharray, "none");
    mark.strokeDashoffset = impliedString(strokeDashoffset, "0");
  }
  mark.target = string(target);
  mark.ariaLabel = string(cariaLabel);
  mark.ariaDescription = string(ariaDescription);
  mark.ariaHidden = string(ariaHidden);
  mark.opacity = impliedNumber(copacity, 1);
  mark.mixBlendMode = impliedString(mixBlendMode, "normal");
  mark.imageFilter = impliedString(imageFilter, "none");
  mark.paintOrder = impliedString(paintOrder, "normal");
  mark.pointerEvents = impliedString(pointerEvents, "auto");
  mark.shapeRendering = impliedString(shapeRendering, "auto");
  return {
    title: { value: title, optional: true, filter: null },
    href: { value: href, optional: true, filter: null },
    ariaLabel: { value: variaLabel, optional: true, filter: null },
    fill: { value: vfill, scale: "auto", optional: true },
    fillOpacity: { value: vfillOpacity, scale: "auto", optional: true },
    stroke: { value: vstroke, scale: "auto", optional: true },
    strokeOpacity: { value: vstrokeOpacity, scale: "auto", optional: true },
    strokeWidth: { value: vstrokeWidth, optional: true },
    opacity: { value: vopacity, scale: "auto", optional: true }
  };
}
function applyTitle(selection2, L) {
  if (L)
    selection2.filter((i) => nonempty(L[i])).append("title").call(applyText, L);
}
function applyTitleGroup(selection2, L) {
  if (L)
    selection2.filter(([i]) => nonempty(L[i])).append("title").call(applyTextGroup, L);
}
function applyText(selection2, T) {
  if (T) selection2.text((i) => formatDefault(T[i]));
}
function applyTextGroup(selection2, T) {
  if (T) selection2.text(([i]) => formatDefault(T[i]));
}
function applyChannelStyles(selection2, { target, tip: tip2 }, {
  ariaLabel: AL,
  title: T,
  fill: F,
  fillOpacity: FO,
  stroke: S,
  strokeOpacity: SO,
  strokeWidth: SW,
  opacity: O,
  href: H
}) {
  if (AL) applyAttr(selection2, "aria-label", (i) => AL[i]);
  if (F) applyAttr(selection2, "fill", (i) => F[i]);
  if (FO) applyAttr(selection2, "fill-opacity", (i) => FO[i]);
  if (S) applyAttr(selection2, "stroke", (i) => S[i]);
  if (SO) applyAttr(selection2, "stroke-opacity", (i) => SO[i]);
  if (SW) applyAttr(selection2, "stroke-width", (i) => SW[i]);
  if (O) applyAttr(selection2, "opacity", (i) => O[i]);
  if (H) applyHref(selection2, (i) => H[i], target);
  if (!tip2) applyTitle(selection2, T);
}
function applyGroupedChannelStyles(selection2, { target, tip: tip2 }, {
  ariaLabel: AL,
  title: T,
  fill: F,
  fillOpacity: FO,
  stroke: S,
  strokeOpacity: SO,
  strokeWidth: SW,
  opacity: O,
  href: H
}) {
  if (AL) applyAttr(selection2, "aria-label", ([i]) => AL[i]);
  if (F) applyAttr(selection2, "fill", ([i]) => F[i]);
  if (FO) applyAttr(selection2, "fill-opacity", ([i]) => FO[i]);
  if (S) applyAttr(selection2, "stroke", ([i]) => S[i]);
  if (SO) applyAttr(selection2, "stroke-opacity", ([i]) => SO[i]);
  if (SW) applyAttr(selection2, "stroke-width", ([i]) => SW[i]);
  if (O) applyAttr(selection2, "opacity", ([i]) => O[i]);
  if (H) applyHref(selection2, ([i]) => H[i], target);
  if (!tip2) applyTitleGroup(selection2, T);
}
function groupAesthetics({
  ariaLabel: AL,
  title: T,
  fill: F,
  fillOpacity: FO,
  stroke: S,
  strokeOpacity: SO,
  strokeWidth: SW,
  opacity: O,
  href: H
}, { tip: tip2 }) {
  return [AL, tip2 ? void 0 : T, F, FO, S, SO, SW, O, H].filter((c4) => c4 !== void 0);
}
function groupZ2(I, Z, z) {
  const G = group(I, (i) => Z[i]);
  if (z === void 0 && G.size > 1 + I.length >> 1) {
    warn(
      `Warning: the implicit z channel has high cardinality. This may occur when the fill or stroke channel is associated with quantitative data rather than ordinal or categorical data. You can suppress this warning by setting the z option explicitly; if this data represents a single series, set z to null.`
    );
  }
  return G.values();
}
function* groupIndex(I, position3, mark, channels) {
  const { z } = mark;
  const { z: Z } = channels;
  const A5 = groupAesthetics(channels, mark);
  const C3 = [...position3, ...A5];
  for (const G of Z ? groupZ2(I, Z, z) : [I]) {
    let Ag;
    let Gg;
    out: for (const i of G) {
      for (const c4 of C3) {
        if (!defined(c4[i])) {
          if (Gg) Gg.push(-1);
          continue out;
        }
      }
      if (Ag === void 0) {
        if (Gg) yield Gg;
        Ag = A5.map((c4) => keyof2(c4[i])), Gg = [i];
        continue;
      }
      Gg.push(i);
      for (let j = 0; j < A5.length; ++j) {
        const k2 = keyof2(A5[j][i]);
        if (k2 !== Ag[j]) {
          yield Gg;
          Ag = A5.map((c4) => keyof2(c4[i])), Gg = [i];
          continue out;
        }
      }
    }
    if (Gg) yield Gg;
  }
}
function applyClip(selection2, mark, dimensions, context) {
  let clipUrl;
  const { clip = context.clip } = mark;
  if (clip === "frame") {
    selection2 = create2("svg:g", context).each(function() {
      this.appendChild(selection2.node());
      selection2.node = () => this;
    });
    clipUrl = getFrameClip(context, dimensions);
  } else if (clip) {
    clipUrl = getGeoClip(clip, context);
  }
  applyAttr(selection2, "aria-label", mark.ariaLabel);
  applyAttr(selection2, "aria-description", mark.ariaDescription);
  applyAttr(selection2, "aria-hidden", mark.ariaHidden);
  applyAttr(selection2, "clip-path", clipUrl);
}
function memoizeClip(clip) {
  const cache = /* @__PURE__ */ new WeakMap();
  return (context, dimensions) => {
    let url = cache.get(context);
    if (!url) {
      const id2 = getClipId();
      select_default2(context.ownerSVGElement).append("clipPath").attr("id", id2).call(clip, context, dimensions);
      cache.set(context, url = `url(#${id2})`);
    }
    return url;
  };
}
var getFrameClip = memoizeClip((clipPath, context, dimensions) => {
  const { width, height, marginLeft, marginRight, marginTop, marginBottom } = dimensions;
  clipPath.append("rect").attr("x", marginLeft).attr("y", marginTop).attr("width", width - marginRight - marginLeft).attr("height", height - marginTop - marginBottom);
});
var geoClipCache = /* @__PURE__ */ new WeakMap();
var sphere = { type: "Sphere" };
function getGeoClip(geo2, context) {
  let cache, url;
  if (!(cache = geoClipCache.get(context))) geoClipCache.set(context, cache = /* @__PURE__ */ new WeakMap());
  if (geo2.type === "Sphere") geo2 = sphere;
  if (!(url = cache.get(geo2))) {
    const id2 = getClipId();
    select_default2(context.ownerSVGElement).append("clipPath").attr("id", id2).append("path").attr("d", context.path()(geo2));
    cache.set(geo2, url = `url(#${id2})`);
  }
  return url;
}
function applyIndirectStyles(selection2, mark, dimensions, context) {
  applyClip(selection2, mark, dimensions, context);
  applyAttr(selection2, "class", mark.className);
  applyAttr(selection2, "fill", mark.fill);
  applyAttr(selection2, "fill-opacity", mark.fillOpacity);
  applyAttr(selection2, "stroke", mark.stroke);
  applyAttr(selection2, "stroke-width", mark.strokeWidth);
  applyAttr(selection2, "stroke-opacity", mark.strokeOpacity);
  applyAttr(selection2, "stroke-linejoin", mark.strokeLinejoin);
  applyAttr(selection2, "stroke-linecap", mark.strokeLinecap);
  applyAttr(selection2, "stroke-miterlimit", mark.strokeMiterlimit);
  applyAttr(selection2, "stroke-dasharray", mark.strokeDasharray);
  applyAttr(selection2, "stroke-dashoffset", mark.strokeDashoffset);
  applyAttr(selection2, "shape-rendering", mark.shapeRendering);
  applyAttr(selection2, "filter", mark.imageFilter);
  applyAttr(selection2, "paint-order", mark.paintOrder);
  const { pointerEvents = context.pointerSticky === false ? "none" : void 0 } = mark;
  applyAttr(selection2, "pointer-events", pointerEvents);
}
function applyDirectStyles(selection2, mark) {
  applyStyle(selection2, "mix-blend-mode", mark.mixBlendMode);
  applyAttr(selection2, "opacity", mark.opacity);
}
function applyHref(selection2, href, target) {
  selection2.each(function(i) {
    const h = href(i);
    if (h != null) {
      const a2 = this.ownerDocument.createElementNS(namespaces_default.svg, "a");
      a2.setAttribute("fill", "inherit");
      a2.setAttributeNS(namespaces_default.xlink, "href", h);
      if (target != null) a2.setAttribute("target", target);
      this.parentNode.insertBefore(a2, this).appendChild(this);
    }
  });
}
function applyAttr(selection2, name, value) {
  if (value != null) selection2.attr(name, value);
}
function applyStyle(selection2, name, value) {
  if (value != null) selection2.style(name, value);
}
function applyTransform(selection2, mark, { x: x3, y: y3 }, tx = offset, ty = offset) {
  tx += mark.dx;
  ty += mark.dy;
  if (x3 == null ? void 0 : x3.bandwidth) tx += x3.bandwidth() / 2;
  if (y3 == null ? void 0 : y3.bandwidth) ty += y3.bandwidth() / 2;
  if (tx || ty) selection2.attr("transform", `translate(${tx},${ty})`);
}
function impliedString(value, impliedValue) {
  if ((value = string(value)) !== impliedValue) return value;
}
function impliedNumber(value, impliedValue) {
  if ((value = number5(value)) !== impliedValue) return value;
}
var validClassName = /^-?([_a-z]|[\240-\377]|\\[0-9a-f]{1,6}(\r\n|[ \t\r\n\f])?|\\[^\r\n\f0-9a-f])([_a-z0-9-]|[\240-\377]|\\[0-9a-f]{1,6}(\r\n|[ \t\r\n\f])?|\\[^\r\n\f0-9a-f])*$/i;
function maybeClassName(name) {
  if (name === void 0) return "plot-d6a7b5";
  name = `${name}`;
  if (!validClassName.test(name)) throw new Error(`invalid class name: ${name}`);
  return name;
}
function applyInlineStyles(selection2, style) {
  if (typeof style === "string") {
    selection2.property("style", style);
  } else if (style != null) {
    for (const element of selection2) {
      Object.assign(element.style, style);
    }
  }
}
function applyFrameAnchor({ frameAnchor }, { width, height, marginTop, marginRight, marginBottom, marginLeft }) {
  return [
    /left$/.test(frameAnchor) ? marginLeft : /right$/.test(frameAnchor) ? width - marginRight : (marginLeft + width - marginRight) / 2,
    /^top/.test(frameAnchor) ? marginTop : /^bottom/.test(frameAnchor) ? height - marginBottom : (marginTop + height - marginBottom) / 2
  ];
}

// node_modules/@observablehq/plot/src/mark.js
var Mark = class {
  constructor(data, channels = {}, options = {}, defaults22) {
    const {
      facet = "auto",
      facetAnchor,
      fx,
      fy,
      sort: sort3,
      dx = 0,
      dy = 0,
      margin = 0,
      marginTop = margin,
      marginRight = margin,
      marginBottom = margin,
      marginLeft = margin,
      className,
      clip = defaults22 == null ? void 0 : defaults22.clip,
      channels: extraChannels,
      tip: tip2,
      render
    } = options;
    this.data = data;
    this.sort = isDomainSort(sort3) ? sort3 : null;
    this.initializer = initializer(options).initializer;
    this.transform = this.initializer ? options.transform : basic(options).transform;
    if (facet === null || facet === false) {
      this.facet = null;
    } else {
      this.facet = keyword(facet === true ? "include" : facet, "facet", ["auto", "include", "exclude", "super"]);
      this.fx = data === singleton && typeof fx === "string" ? [fx] : fx;
      this.fy = data === singleton && typeof fy === "string" ? [fy] : fy;
    }
    this.facetAnchor = maybeFacetAnchor(facetAnchor);
    channels = maybeNamed(channels);
    if (extraChannels !== void 0) channels = { ...maybeChannels(extraChannels), ...channels };
    if (defaults22 !== void 0) channels = { ...styles(this, options, defaults22), ...channels };
    this.channels = Object.fromEntries(
      Object.entries(channels).map(([name, channel]) => {
        if (isOptions(channel.value)) {
          const { value, label = channel.label, scale: scale3 = channel.scale } = channel.value;
          channel = { ...channel, label, scale: scale3, value };
        }
        if (data === singleton && typeof channel.value === "string") {
          const { value } = channel;
          channel = { ...channel, value: [value] };
        }
        return [name, channel];
      }).filter(([name, { value, optional: optional2 }]) => {
        if (value != null) return true;
        if (optional2) return false;
        throw new Error(`missing channel value: ${name}`);
      })
    );
    this.dx = +dx;
    this.dy = +dy;
    this.marginTop = +marginTop;
    this.marginRight = +marginRight;
    this.marginBottom = +marginBottom;
    this.marginLeft = +marginLeft;
    this.clip = maybeClip(clip);
    this.tip = maybeTip(tip2);
    this.className = string(className);
    if (this.facet === "super") {
      if (fx || fy) throw new Error(`super-faceting cannot use fx or fy`);
      for (const name in this.channels) {
        const { scale: scale3 } = channels[name];
        if (scale3 !== "x" && scale3 !== "y") continue;
        throw new Error(`super-faceting cannot use x or y`);
      }
    }
    if (render != null) {
      this.render = composeRender(render, this.render);
    }
  }
  initialize(facets, facetChannels, plotOptions) {
    let data = dataify(this.data);
    if (facets === void 0 && data != null) facets = [range2(data)];
    const originalFacets = facets;
    if (this.transform != null) ({ facets, data } = this.transform(data, facets, plotOptions)), data = dataify(data);
    if (facets !== void 0) facets.original = originalFacets;
    const channels = createChannels(this.channels, data);
    if (this.sort != null) channelDomain(data, facets, channels, facetChannels, this.sort);
    return { data, facets, channels };
  }
  filter(index2, channels, values2) {
    for (const name in channels) {
      const { filter: filter4 = defined } = channels[name];
      if (filter4 !== null) {
        const value = values2[name];
        index2 = index2.filter((i) => filter4(value[i]));
      }
    }
    return index2;
  }
  // If there is a projection, and there are paired x and y channels associated
  // with the x and y scale respectively (and not already in screen coordinates
  // as with an initializer), then apply the projection, replacing the x and y
  // values. Note that the x and y scales themselves don’t exist if there is a
  // projection, but whether the channels are associated with scales still
  // determines whether the projection should apply; think of the projection as
  // a combination xy-scale.
  project(channels, values2, context) {
    for (const cx in channels) {
      if (channels[cx].scale === "x" && /^x|x$/.test(cx)) {
        const cy = cx.replace(/^x|x$/, "y");
        if (cy in channels && channels[cy].scale === "y") {
          project(cx, cy, values2, context.projection);
        }
      }
    }
  }
  scale(channels, scales, context) {
    const values2 = valueObject(channels, scales);
    if (context.projection) this.project(channels, values2, context);
    return values2;
  }
};
function marks(...marks2) {
  marks2.plot = Mark.prototype.plot;
  return marks2;
}
function composeRender(r1, r2) {
  if (r1 == null) return r2 === null ? void 0 : r2;
  if (r2 == null) return r1 === null ? void 0 : r1;
  if (typeof r1 !== "function") throw new TypeError(`invalid render transform: ${r1}`);
  if (typeof r2 !== "function") throw new TypeError(`invalid render transform: ${r2}`);
  return function(i, s2, v2, d, c4, next) {
    return r1.call(this, i, s2, v2, d, c4, (i2, s3, v3, d2, c5) => {
      return r2.call(this, i2, s3, v3, d2, c5, next);
    });
  };
}
function maybeChannels(channels) {
  return Object.fromEntries(
    Object.entries(maybeNamed(channels)).map(([name, channel]) => {
      channel = typeof channel === "string" ? { value: channel, label: name } : maybeValue(channel);
      if (channel.filter === void 0 && channel.scale == null) channel = { ...channel, filter: null };
      return [name, channel];
    })
  );
}
function maybeTip(tip2) {
  return tip2 === true ? "xy" : tip2 === false || tip2 == null ? null : typeof tip2 === "string" ? keyword(tip2, "tip", ["x", "y", "xy"]) : tip2;
}
function withTip(options, pointer2) {
  return (options == null ? void 0 : options.tip) === true ? { ...options, tip: pointer2 } : isObject(options == null ? void 0 : options.tip) && options.tip.pointer === void 0 ? { ...options, tip: { ...options.tip, pointer: pointer2 } } : options;
}

// node_modules/@observablehq/plot/src/dimensions.js
function createDimensions(scales, marks2, options = {}) {
  let marginTopDefault = 0.5 - offset, marginRightDefault = 0.5 + offset, marginBottomDefault = 0.5 + offset, marginLeftDefault = 0.5 - offset;
  for (const { marginTop: marginTop2, marginRight: marginRight2, marginBottom: marginBottom2, marginLeft: marginLeft2 } of marks2) {
    if (marginTop2 > marginTopDefault) marginTopDefault = marginTop2;
    if (marginRight2 > marginRightDefault) marginRightDefault = marginRight2;
    if (marginBottom2 > marginBottomDefault) marginBottomDefault = marginBottom2;
    if (marginLeft2 > marginLeftDefault) marginLeftDefault = marginLeft2;
  }
  let {
    margin,
    marginTop = margin !== void 0 ? margin : marginTopDefault,
    marginRight = margin !== void 0 ? margin : marginRightDefault,
    marginBottom = margin !== void 0 ? margin : marginBottomDefault,
    marginLeft = margin !== void 0 ? margin : marginLeftDefault
  } = options;
  marginTop = +marginTop;
  marginRight = +marginRight;
  marginBottom = +marginBottom;
  marginLeft = +marginLeft;
  let {
    width = 640,
    height = autoHeight(scales, options, {
      width,
      marginTopDefault,
      marginRightDefault,
      marginBottomDefault,
      marginLeftDefault
    }) + Math.max(0, marginTop - marginTopDefault + marginBottom - marginBottomDefault)
  } = options;
  width = +width;
  height = +height;
  const dimensions = {
    width,
    height,
    marginTop,
    marginRight,
    marginBottom,
    marginLeft
  };
  if (scales.fx || scales.fy) {
    let {
      margin: facetMargin,
      marginTop: facetMarginTop = facetMargin !== void 0 ? facetMargin : marginTop,
      marginRight: facetMarginRight = facetMargin !== void 0 ? facetMargin : marginRight,
      marginBottom: facetMarginBottom = facetMargin !== void 0 ? facetMargin : marginBottom,
      marginLeft: facetMarginLeft = facetMargin !== void 0 ? facetMargin : marginLeft
    } = options.facet ?? {};
    facetMarginTop = +facetMarginTop;
    facetMarginRight = +facetMarginRight;
    facetMarginBottom = +facetMarginBottom;
    facetMarginLeft = +facetMarginLeft;
    dimensions.facet = {
      marginTop: facetMarginTop,
      marginRight: facetMarginRight,
      marginBottom: facetMarginBottom,
      marginLeft: facetMarginLeft
    };
  }
  return dimensions;
}
function autoHeight({ x: x3, y: y3, fy, fx }, { projection: projection3, aspectRatio }, { width, marginTopDefault, marginRightDefault, marginBottomDefault, marginLeftDefault }) {
  const nfy = fy ? fy.scale.domain().length || 1 : 1;
  const ar = projectionAspectRatio(projection3);
  if (ar) {
    const nfx = fx ? fx.scale.domain().length : 1;
    const far = (1.1 * nfy - 0.1) / (1.1 * nfx - 0.1) * ar;
    const lar = Math.max(0.1, Math.min(10, far));
    return Math.round((width - marginLeftDefault - marginRightDefault) * lar + marginTopDefault + marginBottomDefault);
  }
  const ny = y3 ? isOrdinalScale(y3) ? y3.scale.domain().length || 1 : Math.max(7, 17 / nfy) : 1;
  if (aspectRatio != null) {
    aspectRatio = +aspectRatio;
    if (!(isFinite(aspectRatio) && aspectRatio > 0)) throw new Error(`invalid aspectRatio: ${aspectRatio}`);
    const ratio = aspectRatioLength("y", y3) / (aspectRatioLength("x", x3) * aspectRatio);
    const fxb = fx ? fx.scale.bandwidth() : 1;
    const fyb = fy ? fy.scale.bandwidth() : 1;
    const w = fxb * (width - marginLeftDefault - marginRightDefault) - x3.insetLeft - x3.insetRight;
    return (ratio * w + y3.insetTop + y3.insetBottom) / fyb + marginTopDefault + marginBottomDefault;
  }
  return !!(y3 || fy) * Math.max(1, Math.min(60, ny * nfy)) * 20 + !!fx * 30 + 60;
}
function aspectRatioLength(k2, scale3) {
  if (!scale3) throw new Error(`aspectRatio requires ${k2} scale`);
  const { type: type2, domain } = scale3;
  let transform2;
  switch (type2) {
    case "linear":
    case "utc":
    case "time":
      transform2 = Number;
      break;
    case "pow": {
      const exponent2 = scale3.scale.exponent();
      transform2 = (x3) => Math.pow(x3, exponent2);
      break;
    }
    case "log":
      transform2 = Math.log;
      break;
    case "point":
    case "band":
      return domain.length;
    default:
      throw new Error(`unsupported ${k2} scale for aspectRatio: ${type2}`);
  }
  const [min4, max5] = extent(domain);
  return Math.abs(transform2(max5) - transform2(min4));
}

// node_modules/@observablehq/plot/src/interactions/pointer.js
var states = /* @__PURE__ */ new WeakMap();
function pointerK(kx2, ky2, { x: x3, y: y3, px, py, maxRadius = 40, channels, render, ...options } = {}) {
  maxRadius = +maxRadius;
  if (px != null) x3 ?? (x3 = null), channels = { ...channels, px: { value: px, scale: "x" } };
  if (py != null) y3 ?? (y3 = null), channels = { ...channels, py: { value: py, scale: "y" } };
  return {
    x: x3,
    y: y3,
    channels,
    ...options,
    // Unlike other composed transforms, the render transform must be the
    // outermost render function because it will re-render dynamically in
    // response to pointer events.
    render: composeRender(function(index2, scales, values2, dimensions, context, next) {
      context = { ...context, pointerSticky: false };
      const svg2 = context.ownerSVGElement;
      const { data } = context.getMarkState(this);
      let state = states.get(svg2);
      if (!state) states.set(svg2, state = { sticky: false, roots: [], renders: [] });
      let renderIndex = state.renders.push(render2) - 1;
      const { x: x4, y: y4, fx, fy } = scales;
      let tx = fx ? fx(index2.fx) - dimensions.marginLeft : 0;
      let ty = fy ? fy(index2.fy) - dimensions.marginTop : 0;
      if (x4 == null ? void 0 : x4.bandwidth) tx += x4.bandwidth() / 2;
      if (y4 == null ? void 0 : y4.bandwidth) ty += y4.bandwidth() / 2;
      const faceted = index2.fi != null;
      let facetState;
      if (faceted) {
        let facetStates = state.facetStates;
        if (!facetStates) state.facetStates = facetStates = /* @__PURE__ */ new Map();
        facetState = facetStates.get(this);
        if (!facetState) facetStates.set(this, facetState = /* @__PURE__ */ new Map());
      }
      const [cx, cy] = applyFrameAnchor(this, dimensions);
      const { px: PX, py: PY } = values2;
      const px2 = PX ? (i2) => PX[i2] : anchorX(values2, cx);
      const py2 = PY ? (i2) => PY[i2] : anchorY(values2, cy);
      let i;
      let g;
      let s2;
      let f;
      function update(ii, ri) {
        if (faceted) {
          if (f) f = cancelAnimationFrame(f);
          if (ii == null) facetState.delete(index2.fi);
          else {
            facetState.set(index2.fi, ri);
            f = requestAnimationFrame(() => {
              f = null;
              for (const [fi, r] of facetState) {
                if (r < ri || r === ri && fi < index2.fi) {
                  ii = null;
                  break;
                }
              }
              render2(ii);
            });
            return;
          }
        }
        render2(ii);
      }
      function render2(ii) {
        if (i === ii && s2 === state.sticky) return;
        i = ii;
        s2 = context.pointerSticky = state.sticky;
        const I = i == null ? [] : [i];
        if (faceted) I.fx = index2.fx, I.fy = index2.fy, I.fi = index2.fi;
        const r = next(I, scales, values2, dimensions, context);
        if (g) {
          if (faceted) {
            const p = g.parentNode;
            const ft = g.getAttribute("transform");
            const mt = r.getAttribute("transform");
            ft ? r.setAttribute("transform", ft) : r.removeAttribute("transform");
            mt ? p.setAttribute("transform", mt) : p.removeAttribute("transform");
            r.removeAttribute("aria-label");
            r.removeAttribute("aria-description");
            r.removeAttribute("aria-hidden");
          }
          g.replaceWith(r);
        }
        state.roots[renderIndex] = g = r;
        if (!(i == null && (facetState == null ? void 0 : facetState.size) > 1)) {
          const value = i == null ? null : isArray(data) ? data[i] : data.get(i);
          context.dispatchValue(value);
        }
        return r;
      }
      function pointermove(event) {
        if (state.sticky || event.pointerType === "mouse" && event.buttons === 1) return;
        let [xp, yp] = pointer_default(event);
        xp -= tx, yp -= ty;
        const kpx = xp < dimensions.marginLeft || xp > dimensions.width - dimensions.marginRight ? 1 : kx2;
        const kpy = yp < dimensions.marginTop || yp > dimensions.height - dimensions.marginBottom ? 1 : ky2;
        let ii = null;
        let ri = maxRadius * maxRadius;
        for (const j of index2) {
          const dx = kpx * (px2(j) - xp);
          const dy = kpy * (py2(j) - yp);
          const rj = dx * dx + dy * dy;
          if (rj <= ri) ii = j, ri = rj;
        }
        if (ii != null && (kx2 !== 1 || ky2 !== 1)) {
          const dx = px2(ii) - xp;
          const dy = py2(ii) - yp;
          ri = dx * dx + dy * dy;
        }
        update(ii, ri);
      }
      function pointerdown(event) {
        if (event.pointerType !== "mouse") return;
        if (i == null) return;
        if (state.sticky && state.roots.some((r) => r == null ? void 0 : r.contains(event.target))) return;
        if (state.sticky) state.sticky = false, state.renders.forEach((r) => r(null));
        else state.sticky = true, render2(i);
        event.stopImmediatePropagation();
      }
      function pointerleave(event) {
        if (event.pointerType !== "mouse") return;
        if (!state.sticky) update(null);
      }
      svg2.addEventListener("pointerenter", pointermove);
      svg2.addEventListener("pointermove", pointermove);
      svg2.addEventListener("pointerdown", pointerdown);
      svg2.addEventListener("pointerleave", pointerleave);
      return render2(null);
    }, render)
  };
}
function pointer(options) {
  return pointerK(1, 1, options);
}
function pointerX(options) {
  return pointerK(1, 0.01, options);
}
function pointerY(options) {
  return pointerK(0.01, 1, options);
}
function anchorX({ x1: X13, x2: X23, x: X3 = X13 }, cx) {
  return X13 && X23 ? (i) => (X13[i] + X23[i]) / 2 : X3 ? (i) => X3[i] : () => cx;
}
function anchorY({ y1: Y13, y2: Y23, y: Y3 = Y13 }, cy) {
  return Y13 && Y23 ? (i) => (Y13[i] + Y23[i]) / 2 : Y3 ? (i) => Y3[i] : () => cy;
}

// node_modules/@observablehq/plot/src/axes.js
function inferFontVariant(scale3) {
  return isOrdinalScale(scale3) && scale3.interval === void 0 ? void 0 : "tabular-nums";
}

// node_modules/@observablehq/plot/src/legends/ramp.js
function legendRamp(color3, options) {
  let {
    label = color3.label,
    tickSize = 6,
    width = 240,
    height = 44 + tickSize,
    marginTop = 18,
    marginRight = 0,
    marginBottom = 16 + tickSize,
    marginLeft = 0,
    style,
    ticks: ticks2 = (width - marginLeft - marginRight) / 64,
    tickFormat: tickFormat2,
    fontVariant = inferFontVariant(color3),
    round: round2 = true,
    opacity: opacity2,
    className
  } = options;
  const context = createContext(options);
  className = maybeClassName(className);
  opacity2 = maybeNumberChannel(opacity2)[1];
  if (tickFormat2 === null) tickFormat2 = () => null;
  const svg2 = create2("svg", context).attr("class", `${className}-ramp`).attr("font-family", "system-ui, sans-serif").attr("font-size", 10).attr("width", width).attr("height", height).attr("viewBox", `0 0 ${width} ${height}`).call(
    (svg3) => (
      // Warning: if you edit this, change defaultClassName.
      svg3.append("style").text(
        `:where(.${className}-ramp) {
  display: block;
  height: auto;
  height: intrinsic;
  max-width: 100%;
  overflow: visible;
}
:where(.${className}-ramp text) {
  white-space: pre;
}`
      )
    )
  ).call(applyInlineStyles, style);
  let tickAdjust = (g) => g.selectAll(".tick line").attr("y1", marginTop + marginBottom - height);
  let x3;
  const applyRange = round2 ? (x4, range4) => x4.rangeRound(range4) : (x4, range4) => x4.range(range4);
  const { type: type2, domain, range: range3, interpolate, scale: scale3, pivot } = color3;
  if (interpolate) {
    const interpolator = range3 === void 0 ? interpolate : piecewise(interpolate.length === 1 ? interpolatePiecewise(interpolate) : interpolate, range3);
    x3 = applyRange(
      scale3.copy(),
      quantize_default(
        number_default(marginLeft, width - marginRight),
        Math.min(domain.length + (pivot !== void 0), range3 === void 0 ? Infinity : range3.length)
      )
    );
    const n = 256;
    const canvas = context.document.createElement("canvas");
    canvas.width = n;
    canvas.height = 1;
    const context2 = canvas.getContext("2d");
    for (let i = 0, j = n - 1; i < n; ++i) {
      context2.fillStyle = interpolator(i / j);
      context2.fillRect(i, 0, 1, 1);
    }
    svg2.append("image").attr("opacity", opacity2).attr("x", marginLeft).attr("y", marginTop).attr("width", width - marginLeft - marginRight).attr("height", height - marginTop - marginBottom).attr("preserveAspectRatio", "none").attr("xlink:href", canvas.toDataURL());
  } else if (type2 === "threshold") {
    const thresholds = domain;
    const thresholdFormat = tickFormat2 === void 0 ? (d) => d : typeof tickFormat2 === "string" ? format(tickFormat2) : tickFormat2;
    x3 = applyRange(linear3().domain([-1, range3.length - 1]), [marginLeft, width - marginRight]);
    svg2.append("g").attr("fill-opacity", opacity2).selectAll().data(range3).enter().append("rect").attr("x", (d, i) => x3(i - 1)).attr("y", marginTop).attr("width", (d, i) => x3(i) - x3(i - 1)).attr("height", height - marginTop - marginBottom).attr("fill", (d) => d);
    ticks2 = map4(thresholds, (_, i) => i);
    tickFormat2 = (i) => thresholdFormat(thresholds[i], i);
  } else {
    x3 = applyRange(band().domain(domain), [marginLeft, width - marginRight]);
    svg2.append("g").attr("fill-opacity", opacity2).selectAll().data(domain).enter().append("rect").attr("x", x3).attr("y", marginTop).attr("width", Math.max(0, x3.bandwidth() - 1)).attr("height", height - marginTop - marginBottom).attr("fill", scale3);
    tickAdjust = () => {
    };
  }
  svg2.append("g").attr("transform", `translate(0,${height - marginBottom})`).call(
    axisBottom(x3).ticks(Array.isArray(ticks2) ? null : ticks2, typeof tickFormat2 === "string" ? tickFormat2 : void 0).tickFormat(typeof tickFormat2 === "function" ? tickFormat2 : void 0).tickSize(tickSize).tickValues(Array.isArray(ticks2) ? ticks2 : null)
  ).attr("font-size", null).attr("font-family", null).attr("font-variant", impliedString(fontVariant, "normal")).call(tickAdjust).call((g) => g.select(".domain").remove());
  if (label !== void 0) {
    svg2.append("text").attr("x", marginLeft).attr("y", marginTop - 6).attr("fill", "currentColor").attr("font-weight", "bold").text(label);
  }
  return svg2.node();
}

// node_modules/@observablehq/plot/src/math.js
var radians3 = Math.PI / 180;

// node_modules/@observablehq/plot/src/marker.js
function markers(mark, { marker, markerStart = marker, markerMid = marker, markerEnd = marker } = {}) {
  mark.markerStart = maybeMarker(markerStart);
  mark.markerMid = maybeMarker(markerMid);
  mark.markerEnd = maybeMarker(markerEnd);
}
function maybeMarker(marker) {
  if (marker == null || marker === false) return null;
  if (marker === true) return markerCircleFill;
  if (typeof marker === "function") return marker;
  switch (`${marker}`.toLowerCase()) {
    case "none":
      return null;
    case "arrow":
      return markerArrow("auto");
    case "arrow-reverse":
      return markerArrow("auto-start-reverse");
    case "dot":
      return markerDot;
    case "circle":
    case "circle-fill":
      return markerCircleFill;
    case "circle-stroke":
      return markerCircleStroke;
    case "tick":
      return markerTick("auto");
    case "tick-x":
      return markerTick(90);
    case "tick-y":
      return markerTick(0);
  }
  throw new Error(`invalid marker: ${marker}`);
}
function markerArrow(orient) {
  return (color3, context) => create2("svg:marker", context).attr("viewBox", "-5 -5 10 10").attr("markerWidth", 6.67).attr("markerHeight", 6.67).attr("orient", orient).attr("fill", "none").attr("stroke", color3).attr("stroke-width", 1.5).attr("stroke-linecap", "round").attr("stroke-linejoin", "round").call((marker) => marker.append("path").attr("d", "M-1.5,-3l3,3l-3,3")).node();
}
function markerDot(color3, context) {
  return create2("svg:marker", context).attr("viewBox", "-5 -5 10 10").attr("markerWidth", 6.67).attr("markerHeight", 6.67).attr("fill", color3).attr("stroke", "none").call((marker) => marker.append("circle").attr("r", 2.5)).node();
}
function markerCircleFill(color3, context) {
  return create2("svg:marker", context).attr("viewBox", "-5 -5 10 10").attr("markerWidth", 6.67).attr("markerHeight", 6.67).attr("fill", color3).attr("stroke", "var(--plot-background)").attr("stroke-width", 1.5).call((marker) => marker.append("circle").attr("r", 3)).node();
}
function markerCircleStroke(color3, context) {
  return create2("svg:marker", context).attr("viewBox", "-5 -5 10 10").attr("markerWidth", 6.67).attr("markerHeight", 6.67).attr("fill", "var(--plot-background)").attr("stroke", color3).attr("stroke-width", 1.5).call((marker) => marker.append("circle").attr("r", 3)).node();
}
function markerTick(orient) {
  return (color3, context) => create2("svg:marker", context).attr("viewBox", "-3 -3 6 6").attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", orient).attr("stroke", color3).call((marker) => marker.append("path").attr("d", "M0,-3v6")).node();
}
var nextMarkerId = 0;
function applyMarkers(path2, mark, { stroke: S }, context) {
  return applyMarkersColor(path2, mark, S && ((i) => S[i]), null, context);
}
function applyGroupedMarkers(path2, mark, { stroke: S, z: Z }, context) {
  return applyMarkersColor(path2, mark, S && (([i]) => S[i]), Z, context);
}
var START = 1;
var END = 2;
function getGroupedOrientation(path2, Z) {
  const O = new Uint8Array(Z.length);
  const D3 = path2.data().filter((I) => I.length > 1);
  const n = D3.length;
  for (let i = 0, z = unset; i < n; ++i) {
    const I = D3[i];
    if (I.length > 1) {
      const i2 = I[0];
      if (z !== (z = keyof2(Z[i2]))) O[i2] |= START;
    }
  }
  for (let i = n - 1, z = unset; i >= 0; --i) {
    const I = D3[i];
    if (I.length > 1) {
      const i2 = I[0];
      if (z !== (z = keyof2(Z[i2]))) O[i2] |= END;
    }
  }
  return ([i]) => O[i];
}
function applyMarkersColor(path2, { markerStart, markerMid, markerEnd, stroke }, strokeof = () => stroke, Z, context) {
  if (!markerStart && !markerMid && !markerEnd) return;
  const iriByMarkerColor = /* @__PURE__ */ new Map();
  const orient = Z && getGroupedOrientation(path2, Z);
  function applyMarker(name, marker, filter4) {
    return function(i) {
      if (filter4 && !filter4(i)) return;
      const color3 = strokeof(i);
      let iriByColor = iriByMarkerColor.get(marker);
      if (!iriByColor) iriByMarkerColor.set(marker, iriByColor = /* @__PURE__ */ new Map());
      let iri = iriByColor.get(color3);
      if (!iri) {
        const node = this.parentNode.insertBefore(marker(color3, context), this);
        const id2 = `plot-marker-${++nextMarkerId}`;
        node.setAttribute("id", id2);
        iriByColor.set(color3, iri = `url(#${id2})`);
      }
      this.setAttribute(name, iri);
    };
  }
  if (markerStart) path2.each(applyMarker("marker-start", markerStart, orient && ((i) => orient(i) & START)));
  if (markerMid && orient) path2.each(applyMarker("marker-start", markerMid, (i) => !(orient(i) & START)));
  if (markerMid) path2.each(applyMarker("marker-mid", markerMid));
  if (markerEnd) path2.each(applyMarker("marker-end", markerEnd, orient && ((i) => orient(i) & END)));
}

// node_modules/@observablehq/plot/src/transforms/inset.js
function maybeInsetX({ inset, insetLeft, insetRight, ...options } = {}) {
  [insetLeft, insetRight] = maybeInset(inset, insetLeft, insetRight);
  return { inset, insetLeft, insetRight, ...options };
}
function maybeInsetY({ inset, insetTop, insetBottom, ...options } = {}) {
  [insetTop, insetBottom] = maybeInset(inset, insetTop, insetBottom);
  return { inset, insetTop, insetBottom, ...options };
}
function maybeInset(inset, inset1, inset2) {
  return inset === void 0 && inset1 === void 0 && inset2 === void 0 ? offset ? [1, 0] : [0.5, 0.5] : [inset1, inset2];
}

// node_modules/@observablehq/plot/src/transforms/interval.js
function maybeIntervalValue(value, { interval: interval2 }) {
  value = { ...maybeValue(value) };
  value.interval = maybeInterval(value.interval === void 0 ? interval2 : value.interval);
  return value;
}
function maybeIntervalK(k2, maybeInsetK, options, trivial) {
  const { [k2]: v2, [`${k2}1`]: v1, [`${k2}2`]: v22 } = options;
  const { value, interval: interval2 } = maybeIntervalValue(v2, options);
  if (value == null || interval2 == null && !trivial) return options;
  const label = labelof(v2);
  if (interval2 == null) {
    let V;
    const kv = { transform: (data) => V || (V = valueof(data, value)), label };
    return {
      ...options,
      [k2]: void 0,
      [`${k2}1`]: v1 === void 0 ? kv : v1,
      [`${k2}2`]: v22 === void 0 && !(v1 === v22 && trivial) ? kv : v22
    };
  }
  let D1, V1;
  function transform2(data) {
    if (V1 !== void 0 && data === D1) return V1;
    return V1 = map4(valueof(D1 = data, value), (v3) => interval2.floor(v3));
  }
  return maybeInsetK({
    ...options,
    [k2]: void 0,
    [`${k2}1`]: v1 === void 0 ? { transform: transform2, label } : v1,
    [`${k2}2`]: v22 === void 0 ? { transform: (data) => transform2(data).map((v3) => interval2.offset(v3)), label } : v22
  });
}
function maybeIntervalMidK(k2, maybeInsetK, options) {
  const { [k2]: v2 } = options;
  const { value, interval: interval2 } = maybeIntervalValue(v2, options);
  if (value == null || interval2 == null) return options;
  return maybeInsetK({
    ...options,
    [k2]: {
      label: labelof(v2),
      transform: (data) => {
        const V1 = map4(valueof(data, value), (v3) => interval2.floor(v3));
        const V2 = V1.map((v3) => interval2.offset(v3));
        return V1.map(
          isTemporal(V1) ? (v1, v22) => v1 == null || isNaN(v1 = +v1) || (v22 = V2[v22], v22 == null) || isNaN(v22 = +v22) ? void 0 : new Date((v1 + v22) / 2) : (v1, v22) => v1 == null || (v22 = V2[v22], v22 == null) ? NaN : (+v1 + +v22) / 2
        );
      }
    }
  });
}
function maybeTrivialIntervalX(options = {}) {
  return maybeIntervalK("x", maybeInsetX, options, true);
}
function maybeTrivialIntervalY(options = {}) {
  return maybeIntervalK("y", maybeInsetY, options, true);
}
function maybeIntervalX(options = {}) {
  return maybeIntervalK("x", maybeInsetX, options);
}
function maybeIntervalY(options = {}) {
  return maybeIntervalK("y", maybeInsetY, options);
}
function maybeIntervalMidX(options = {}) {
  return maybeIntervalMidK("x", maybeInsetX, options);
}
function maybeIntervalMidY(options = {}) {
  return maybeIntervalMidK("y", maybeInsetY, options);
}

// node_modules/@observablehq/plot/src/marks/rule.js
var defaults = {
  ariaLabel: "rule",
  fill: null,
  stroke: "currentColor"
};
var RuleX = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y1: y12, y2: y22, inset = 0, insetTop = inset, insetBottom = inset } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y1: { value: y12, scale: "y", optional: true },
        y2: { value: y22, scale: "y", optional: true }
      },
      withTip(options, "x"),
      defaults
    );
    this.insetTop = number5(insetTop);
    this.insetBottom = number5(insetBottom);
    markers(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y1: Y13, y2: Y23 } = channels;
    const { width, height, marginTop, marginRight, marginLeft, marginBottom } = dimensions;
    const { insetTop, insetBottom } = this;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3 }, offset, 0).call(
      (g) => g.selectAll().data(index2).enter().append("line").call(applyDirectStyles, this).attr("x1", X3 ? (i) => X3[i] : (marginLeft + width - marginRight) / 2).attr("x2", X3 ? (i) => X3[i] : (marginLeft + width - marginRight) / 2).attr("y1", Y13 && !isCollapsed(y3) ? (i) => Y13[i] + insetTop : marginTop + insetTop).attr(
        "y2",
        Y23 && !isCollapsed(y3) ? y3.bandwidth ? (i) => Y23[i] + y3.bandwidth() - insetBottom : (i) => Y23[i] - insetBottom : height - marginBottom - insetBottom
      ).call(applyChannelStyles, this, channels).call(applyMarkers, this, channels, context)
    ).node();
  }
};
var RuleY = class extends Mark {
  constructor(data, options = {}) {
    const { x1: x12, x2: x22, y: y3, inset = 0, insetRight = inset, insetLeft = inset } = options;
    super(
      data,
      {
        y: { value: y3, scale: "y", optional: true },
        x1: { value: x12, scale: "x", optional: true },
        x2: { value: x22, scale: "x", optional: true }
      },
      withTip(options, "y"),
      defaults
    );
    this.insetRight = number5(insetRight);
    this.insetLeft = number5(insetLeft);
    markers(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { y: Y3, x1: X13, x2: X23 } = channels;
    const { width, height, marginTop, marginRight, marginLeft, marginBottom } = dimensions;
    const { insetLeft, insetRight } = this;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { y: Y3 && y3 }, 0, offset).call(
      (g) => g.selectAll().data(index2).enter().append("line").call(applyDirectStyles, this).attr("x1", X13 && !isCollapsed(x3) ? (i) => X13[i] + insetLeft : marginLeft + insetLeft).attr(
        "x2",
        X23 && !isCollapsed(x3) ? x3.bandwidth ? (i) => X23[i] + x3.bandwidth() - insetRight : (i) => X23[i] - insetRight : width - marginRight - insetRight
      ).attr("y1", Y3 ? (i) => Y3[i] : (marginTop + height - marginBottom) / 2).attr("y2", Y3 ? (i) => Y3[i] : (marginTop + height - marginBottom) / 2).call(applyChannelStyles, this, channels).call(applyMarkers, this, channels, context)
    ).node();
  }
};
function ruleX(data, options) {
  let { x: x3 = identity6, y: y3, y1: y12, y2: y22, ...rest } = maybeIntervalY(options);
  [y12, y22] = maybeOptionalZero(y3, y12, y22);
  return new RuleX(data, { ...rest, x: x3, y1: y12, y2: y22 });
}
function ruleY(data, options) {
  let { y: y3 = identity6, x: x3, x1: x12, x2: x22, ...rest } = maybeIntervalX(options);
  [x12, x22] = maybeOptionalZero(x3, x12, x22);
  return new RuleY(data, { ...rest, y: y3, x1: x12, x2: x22 });
}
function maybeOptionalZero(x3, x12, x22) {
  if (x3 == null) {
    if (x12 === void 0) {
      if (x22 !== void 0) return [0, x22];
    } else {
      if (x22 === void 0) return [0, x12];
    }
  } else if (x12 === void 0) {
    return x22 === void 0 ? [0, x3] : [x3, x22];
  } else if (x22 === void 0) {
    return [x3, x12];
  }
  return [x12, x22];
}

// node_modules/@observablehq/plot/src/template.js
function template(strings, ...parts) {
  let n = parts.length;
  for (let j = 0, copy3 = true; j < n; ++j) {
    if (typeof parts[j] !== "function") {
      if (copy3) {
        strings = strings.slice();
        copy3 = false;
      }
      strings.splice(j, 2, strings[j] + parts[j] + strings[j + 1]);
      parts.splice(j, 1);
      --j, --n;
    }
  }
  return (i) => {
    let s2 = strings[0];
    for (let j = 0; j < n; ++j) {
      s2 += parts[j](i) + strings[j + 1];
    }
    return s2;
  };
}

// node_modules/@observablehq/plot/src/marks/text.js
var defaults2 = {
  ariaLabel: "text",
  strokeLinejoin: "round",
  strokeWidth: 3,
  paintOrder: "stroke"
};
var softHyphen = "­";
var Text = class extends Mark {
  constructor(data, options = {}) {
    const {
      x: x3,
      y: y3,
      text: text2 = isIterable(data) && isTextual(data) ? identity6 : indexOf,
      frameAnchor,
      textAnchor = /right$/i.test(frameAnchor) ? "end" : /left$/i.test(frameAnchor) ? "start" : "middle",
      lineAnchor = /^top/i.test(frameAnchor) ? "top" : /^bottom/i.test(frameAnchor) ? "bottom" : "middle",
      lineHeight = 1,
      lineWidth = Infinity,
      textOverflow,
      monospace,
      fontFamily = monospace ? "ui-monospace, monospace" : void 0,
      fontSize,
      fontStyle,
      fontVariant,
      fontWeight,
      rotate
    } = options;
    const [vrotate, crotate] = maybeNumberChannel(rotate, 0);
    const [vfontSize, cfontSize] = maybeFontSizeChannel(fontSize);
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        fontSize: { value: vfontSize, optional: true },
        rotate: { value: numberChannel(vrotate), optional: true },
        text: { value: text2, filter: nonempty, optional: true }
      },
      options,
      defaults2
    );
    this.rotate = crotate;
    this.textAnchor = impliedString(textAnchor, "middle");
    this.lineAnchor = keyword(lineAnchor, "lineAnchor", ["top", "middle", "bottom"]);
    this.lineHeight = +lineHeight;
    this.lineWidth = +lineWidth;
    this.textOverflow = maybeTextOverflow(textOverflow);
    this.monospace = !!monospace;
    this.fontFamily = string(fontFamily);
    this.fontSize = cfontSize;
    this.fontStyle = string(fontStyle);
    this.fontVariant = string(fontVariant);
    this.fontWeight = string(fontWeight);
    this.frameAnchor = maybeFrameAnchor(frameAnchor);
    if (!(this.lineWidth >= 0)) throw new Error(`invalid lineWidth: ${lineWidth}`);
    this.splitLines = splitter2(this);
    this.clipLine = clipper(this);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, rotate: R, text: T, title: TL, fontSize: FS } = channels;
    const { rotate } = this;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyIndirectTextStyles, this, T, dimensions).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      (g) => g.selectAll().data(index2).enter().append("text").call(applyDirectStyles, this).call(applyMultilineText, this, T, TL).attr(
        "transform",
        template`translate(${X3 ? (i) => X3[i] : cx},${Y3 ? (i) => Y3[i] : cy})${R ? (i) => ` rotate(${R[i]})` : rotate ? ` rotate(${rotate})` : ``}`
      ).call(applyAttr, "font-size", FS && ((i) => FS[i])).call(applyChannelStyles, this, channels)
    ).node();
  }
};
function maybeTextOverflow(textOverflow) {
  return textOverflow == null ? null : keyword(textOverflow, "textOverflow", [
    "clip",
    // shorthand for clip-end
    "ellipsis",
    // … ellipsis-end
    "clip-start",
    "clip-end",
    "ellipsis-start",
    "ellipsis-middle",
    "ellipsis-end"
  ]).replace(/^(clip|ellipsis)$/, "$1-end");
}
function applyMultilineText(selection2, mark, T, TL) {
  if (!T) return;
  const { lineAnchor, lineHeight, textOverflow, splitLines, clipLine } = mark;
  selection2.each(function(i) {
    const lines = splitLines(formatDefault(T[i]) ?? "").map(clipLine);
    const n = lines.length;
    const y3 = lineAnchor === "top" ? 0.71 : lineAnchor === "bottom" ? 1 - n : (164 - n * 100) / 200;
    if (n > 1) {
      let m = 0;
      for (let i2 = 0; i2 < n; ++i2) {
        ++m;
        if (!lines[i2]) continue;
        const tspan = this.ownerDocument.createElementNS(namespaces_default.svg, "tspan");
        tspan.setAttribute("x", 0);
        if (i2 === m - 1) tspan.setAttribute("y", `${(y3 + i2) * lineHeight}em`);
        else tspan.setAttribute("dy", `${m * lineHeight}em`);
        tspan.textContent = lines[i2];
        this.appendChild(tspan);
        m = 0;
      }
    } else {
      if (y3) this.setAttribute("y", `${y3 * lineHeight}em`);
      this.textContent = lines[0];
    }
    if (textOverflow && !TL && lines[0] !== T[i]) {
      const title = this.ownerDocument.createElementNS(namespaces_default.svg, "title");
      title.textContent = T[i];
      this.appendChild(title);
    }
  });
}
function text(data, { x: x3, y: y3, ...options } = {}) {
  if (options.frameAnchor === void 0) [x3, y3] = maybeTuple(x3, y3);
  return new Text(data, { ...options, x: x3, y: y3 });
}
function textX(data, { x: x3 = identity6, ...options } = {}) {
  return new Text(data, maybeIntervalMidY({ ...options, x: x3 }));
}
function textY(data, { y: y3 = identity6, ...options } = {}) {
  return new Text(data, maybeIntervalMidX({ ...options, y: y3 }));
}
function applyIndirectTextStyles(selection2, mark, T) {
  applyAttr(selection2, "text-anchor", mark.textAnchor);
  applyAttr(selection2, "font-family", mark.fontFamily);
  applyAttr(selection2, "font-size", mark.fontSize);
  applyAttr(selection2, "font-style", mark.fontStyle);
  applyAttr(selection2, "font-variant", mark.fontVariant === void 0 ? inferFontVariant2(T) : mark.fontVariant);
  applyAttr(selection2, "font-weight", mark.fontWeight);
}
function inferFontVariant2(T) {
  return T && (isNumeric(T) || isTemporal(T)) ? "tabular-nums" : void 0;
}
var fontSizes = /* @__PURE__ */ new Set([
  // global keywords
  "inherit",
  "initial",
  "revert",
  "unset",
  // absolute keywords
  "xx-small",
  "x-small",
  "small",
  "medium",
  "large",
  "x-large",
  "xx-large",
  "xxx-large",
  // relative keywords
  "larger",
  "smaller"
]);
function maybeFontSizeChannel(fontSize) {
  if (fontSize == null || typeof fontSize === "number") return [void 0, fontSize];
  if (typeof fontSize !== "string") return [fontSize, void 0];
  fontSize = fontSize.trim().toLowerCase();
  return fontSizes.has(fontSize) || /^[+-]?\d*\.?\d+(e[+-]?\d+)?(\w*|%)$/.test(fontSize) ? [void 0, fontSize] : [fontSize, void 0];
}
function lineWrap(input, maxWidth, widthof) {
  const lines = [];
  let lineStart, lineEnd = 0;
  for (const [wordStart, wordEnd, required2] of lineBreaks(input)) {
    if (lineStart === void 0) lineStart = wordStart;
    if (lineEnd > lineStart && widthof(input, lineStart, wordEnd) > maxWidth) {
      lines.push(input.slice(lineStart, lineEnd) + (input[lineEnd - 1] === softHyphen ? "-" : ""));
      lineStart = wordStart;
    }
    if (required2) {
      lines.push(input.slice(lineStart, wordEnd));
      lineStart = void 0;
      continue;
    }
    lineEnd = wordEnd;
  }
  return lines;
}
function* lineBreaks(input) {
  let i = 0, j = 0;
  const n = input.length;
  while (j < n) {
    let k2 = 1;
    switch (input[j]) {
      case softHyphen:
      case "-":
        ++j;
        yield [i, j, false];
        i = j;
        break;
      case " ":
        yield [i, j, false];
        while (input[++j] === " ") ;
        i = j;
        break;
      case "\r":
        if (input[j + 1] === "\n") ++k2;
      // falls through
      case "\n":
        yield [i, j, true];
        j += k2;
        i = j;
        break;
      default:
        ++j;
        break;
    }
  }
  yield [i, j, true];
}
var defaultWidthMap = {
  a: 56,
  b: 63,
  c: 57,
  d: 63,
  e: 58,
  f: 37,
  g: 62,
  h: 60,
  i: 26,
  j: 26,
  k: 55,
  l: 26,
  m: 88,
  n: 60,
  o: 60,
  p: 62,
  q: 62,
  r: 39,
  s: 54,
  t: 38,
  u: 60,
  v: 55,
  w: 79,
  x: 54,
  y: 55,
  z: 55,
  A: 69,
  B: 67,
  C: 73,
  D: 74,
  E: 61,
  F: 58,
  G: 76,
  H: 75,
  I: 28,
  J: 55,
  K: 67,
  L: 58,
  M: 89,
  N: 75,
  O: 78,
  P: 65,
  Q: 78,
  R: 67,
  S: 65,
  T: 65,
  U: 75,
  V: 69,
  W: 98,
  X: 69,
  Y: 67,
  Z: 67,
  0: 64,
  1: 48,
  2: 62,
  3: 64,
  4: 66,
  5: 63,
  6: 65,
  7: 58,
  8: 65,
  9: 65,
  " ": 29,
  "!": 32,
  '"': 49,
  "'": 31,
  "(": 39,
  ")": 39,
  ",": 31,
  "-": 48,
  ".": 31,
  "/": 32,
  ":": 31,
  ";": 31,
  "?": 52,
  "‘": 31,
  "’": 31,
  "“": 47,
  "”": 47,
  "…": 82
};
function defaultWidth(text2, start2 = 0, end = text2.length) {
  let sum4 = 0;
  for (let i = start2; i < end; i = readCharacter(text2, i)) {
    sum4 += defaultWidthMap[text2[i]] ?? (isPictographic(text2, i) ? 120 : defaultWidthMap.e);
  }
  return sum4;
}
function monospaceWidth(text2, start2 = 0, end = text2.length) {
  let sum4 = 0;
  for (let i = start2; i < end; i = readCharacter(text2, i)) {
    sum4 += isPictographic(text2, i) ? 126 : 63;
  }
  return sum4;
}
function splitter2({ monospace, lineWidth, textOverflow }) {
  if (textOverflow != null || lineWidth == Infinity) return (text2) => text2.split(/\r\n?|\n/g);
  const widthof = monospace ? monospaceWidth : defaultWidth;
  const maxWidth = lineWidth * 100;
  return (text2) => lineWrap(text2, maxWidth, widthof);
}
function clipper({ monospace, lineWidth, textOverflow }) {
  if (textOverflow == null || lineWidth == Infinity) return (text2) => text2;
  const widthof = monospace ? monospaceWidth : defaultWidth;
  const maxWidth = lineWidth * 100;
  switch (textOverflow) {
    case "clip-start":
      return (text2) => clipStart(text2, maxWidth, widthof, "");
    case "clip-end":
      return (text2) => clipEnd(text2, maxWidth, widthof, "");
    case "ellipsis-start":
      return (text2) => clipStart(text2, maxWidth, widthof, ellipsis);
    case "ellipsis-middle":
      return (text2) => clipMiddle(text2, maxWidth, widthof, ellipsis);
    case "ellipsis-end":
      return (text2) => clipEnd(text2, maxWidth, widthof, ellipsis);
  }
}
var ellipsis = "…";
function cut(text2, width, widthof, inset) {
  const I = [];
  let w = 0;
  for (let i = 0, j = 0, n = text2.length; i < n; i = j) {
    j = readCharacter(text2, i);
    const l = widthof(text2, i, j);
    if (w + l > width) {
      w += inset;
      while (w > width && i > 0) j = i, i = I.pop(), w -= widthof(text2, i, j);
      return [i, width - w];
    }
    w += l;
    I.push(i);
  }
  return [-1, 0];
}
function clipEnd(text2, width, widthof, ellipsis2) {
  text2 = text2.trim();
  const e = widthof(ellipsis2);
  const [i] = cut(text2, width, widthof, e);
  return i < 0 ? text2 : text2.slice(0, i).trimEnd() + ellipsis2;
}
function clipMiddle(text2, width, widthof, ellipsis2) {
  text2 = text2.trim();
  const w = widthof(text2);
  if (w <= width) return text2;
  const e = widthof(ellipsis2) / 2;
  const [i, ei] = cut(text2, width / 2, widthof, e);
  const [j] = cut(text2, w - width / 2 - ei + e, widthof, -e);
  return j < 0 ? ellipsis2 : text2.slice(0, i).trimEnd() + ellipsis2 + text2.slice(readCharacter(text2, j)).trimStart();
}
function clipStart(text2, width, widthof, ellipsis2) {
  text2 = text2.trim();
  const w = widthof(text2);
  if (w <= width) return text2;
  const e = widthof(ellipsis2);
  const [j] = cut(text2, w - width + e, widthof, -e);
  return j < 0 ? ellipsis2 : ellipsis2 + text2.slice(readCharacter(text2, j)).trimStart();
}
var reCombiner = /[\p{Combining_Mark}\p{Emoji_Modifier}]+/uy;
var rePictographic = new RegExp("\\p{Extended_Pictographic}", "uy");
function readCharacter(text2, i) {
  i += isSurrogatePair(text2, i) ? 2 : 1;
  if (isCombiner(text2, i)) i = reCombiner.lastIndex;
  if (isZeroWidthJoiner(text2, i)) return readCharacter(text2, i + 1);
  return i;
}
function isAscii(text2, i) {
  return text2.charCodeAt(i) < 128;
}
function isSurrogatePair(text2, i) {
  const hi = text2.charCodeAt(i);
  if (hi >= 55296 && hi < 56320) {
    const lo = text2.charCodeAt(i + 1);
    return lo >= 56320 && lo < 57344;
  }
  return false;
}
function isZeroWidthJoiner(text2, i) {
  return text2.charCodeAt(i) === 8205;
}
function isCombiner(text2, i) {
  return isAscii(text2, i) ? false : (reCombiner.lastIndex = i, reCombiner.test(text2));
}
function isPictographic(text2, i) {
  return isAscii(text2, i) ? false : (rePictographic.lastIndex = i, rePictographic.test(text2));
}

// node_modules/@observablehq/plot/src/marks/vector.js
var defaults3 = {
  ariaLabel: "vector",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinejoin: "round",
  strokeLinecap: "round"
};
var defaultRadius = 3.5;
var wingRatio = defaultRadius * 5;
var shapeArrow = {
  draw(context, l, r) {
    const wing = l * r / wingRatio;
    context.moveTo(0, 0);
    context.lineTo(0, -l);
    context.moveTo(-wing, wing - l);
    context.lineTo(0, -l);
    context.lineTo(wing, wing - l);
  }
};
var shapeSpike = {
  draw(context, l, r) {
    context.moveTo(-r, 0);
    context.lineTo(0, -l);
    context.lineTo(r, 0);
  }
};
var shapes = /* @__PURE__ */ new Map([
  ["arrow", shapeArrow],
  ["spike", shapeSpike]
]);
function isShapeObject(value) {
  return value && typeof value.draw === "function";
}
function maybeShape(shape) {
  if (isShapeObject(shape)) return shape;
  const value = shapes.get(`${shape}`.toLowerCase());
  if (value) return value;
  throw new Error(`invalid shape: ${shape}`);
}
var Vector = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y: y3, r = defaultRadius, length: length3, rotate, shape = shapeArrow, anchor = "middle", frameAnchor } = options;
    const [vl, cl] = maybeNumberChannel(length3, 12);
    const [vr, cr] = maybeNumberChannel(rotate, 0);
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        length: { value: vl, scale: "length", optional: true },
        rotate: { value: vr, optional: true }
      },
      options,
      defaults3
    );
    this.r = +r;
    this.length = cl;
    this.rotate = cr;
    this.shape = maybeShape(shape);
    this.anchor = keyword(anchor, "anchor", ["start", "middle", "end"]);
    this.frameAnchor = maybeFrameAnchor(frameAnchor);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, length: L, rotate: A5 } = channels;
    const { length: length3, rotate, anchor, shape, r } = this;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      (g) => g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).attr(
        "transform",
        template`translate(${X3 ? (i) => X3[i] : cx},${Y3 ? (i) => Y3[i] : cy})${A5 ? (i) => ` rotate(${A5[i]})` : rotate ? ` rotate(${rotate})` : ``}${anchor === "start" ? `` : anchor === "end" ? L ? (i) => ` translate(0,${L[i]})` : ` translate(0,${length3})` : L ? (i) => ` translate(0,${L[i] / 2})` : ` translate(0,${length3 / 2})`}`
      ).attr(
        "d",
        L ? (i) => {
          const p = pathRound();
          shape.draw(p, L[i], r);
          return p;
        } : (() => {
          const p = pathRound();
          shape.draw(p, length3, r);
          return p;
        })()
      ).call(applyChannelStyles, this, channels)
    ).node();
  }
};
function vector(data, options = {}) {
  let { x: x3, y: y3, ...rest } = options;
  if (options.frameAnchor === void 0) [x3, y3] = maybeTuple(x3, y3);
  return new Vector(data, { ...rest, x: x3, y: y3 });
}
function vectorX(data, options = {}) {
  const { x: x3 = identity6, ...rest } = options;
  return new Vector(data, { ...rest, x: x3 });
}
function vectorY(data, options = {}) {
  const { y: y3 = identity6, ...rest } = options;
  return new Vector(data, { ...rest, y: y3 });
}
function spike(data, options = {}) {
  const {
    shape = shapeSpike,
    stroke = defaults3.stroke,
    strokeWidth = 1,
    fill = stroke,
    fillOpacity = 0.3,
    anchor = "start",
    ...rest
  } = options;
  return vector(data, { ...rest, shape, stroke, strokeWidth, fill, fillOpacity, anchor });
}

// node_modules/@observablehq/plot/src/marks/axis.js
function maybeData(data, options) {
  if (arguments.length < 2 && !isIterable(data)) options = data, data = null;
  if (options === void 0) options = {};
  return [data, options];
}
function maybeAnchor2({ anchor } = {}, anchors) {
  return anchor === void 0 ? anchors[0] : keyword(anchor, "anchor", anchors);
}
function anchorY2(options) {
  return maybeAnchor2(options, ["left", "right"]);
}
function anchorFy(options) {
  return maybeAnchor2(options, ["right", "left"]);
}
function anchorX2(options) {
  return maybeAnchor2(options, ["bottom", "top"]);
}
function anchorFx(options) {
  return maybeAnchor2(options, ["top", "bottom"]);
}
function axisY() {
  const [data, options] = maybeData(...arguments);
  return axisKy("y", anchorY2(options), data, options);
}
function axisFy() {
  const [data, options] = maybeData(...arguments);
  return axisKy("fy", anchorFy(options), data, options);
}
function axisX() {
  const [data, options] = maybeData(...arguments);
  return axisKx("x", anchorX2(options), data, options);
}
function axisFx() {
  const [data, options] = maybeData(...arguments);
  return axisKx("fx", anchorFx(options), data, options);
}
function axisKy(k2, anchor, data, {
  color: color3 = "currentColor",
  opacity: opacity2 = 1,
  stroke = color3,
  strokeOpacity = opacity2,
  strokeWidth = 1,
  fill = color3,
  fillOpacity = opacity2,
  textAnchor,
  textStroke,
  textStrokeOpacity,
  textStrokeWidth,
  tickSize = k2 === "y" ? 6 : 0,
  tickPadding,
  tickRotate,
  x: x3,
  margin,
  marginTop = margin === void 0 ? 20 : margin,
  marginRight = margin === void 0 ? anchor === "right" ? 40 : 0 : margin,
  marginBottom = margin === void 0 ? 20 : margin,
  marginLeft = margin === void 0 ? anchor === "left" ? 40 : 0 : margin,
  label,
  labelAnchor,
  labelArrow,
  labelOffset,
  ariaLabel = `${k2}-axis`,
  ...options
}) {
  tickSize = number5(tickSize);
  tickPadding = number5(tickPadding);
  tickRotate = number5(tickRotate);
  if (labelAnchor !== void 0) labelAnchor = keyword(labelAnchor, "labelAnchor", ["center", "top", "bottom"]);
  labelArrow = maybeLabelArrow(labelArrow);
  return marks(
    tickSize && !isNoneish(stroke) ? axisTickKy(k2, anchor, data, {
      stroke,
      strokeOpacity,
      strokeWidth,
      tickSize,
      tickPadding,
      tickRotate,
      x: x3,
      ariaLabel,
      ...options
    }) : null,
    !isNoneish(fill) ? axisTextKy(k2, anchor, data, {
      fill,
      fillOpacity,
      stroke: textStroke,
      strokeOpacity: textStrokeOpacity,
      strokeWidth: textStrokeWidth,
      textAnchor,
      tickSize,
      tickPadding,
      tickRotate,
      x: x3,
      marginTop,
      marginRight,
      marginBottom,
      marginLeft,
      ariaLabel,
      ...options
    }) : null,
    !isNoneish(fill) && label !== null ? text(
      [],
      labelOptions({ fill, fillOpacity, ...options }, function(data2, facets, channels, scales, dimensions) {
        const scale3 = scales[k2];
        const { marginTop: marginTop2, marginRight: marginRight2, marginBottom: marginBottom2, marginLeft: marginLeft2 } = k2 === "y" && dimensions.inset || dimensions;
        const cla = labelAnchor ?? (scale3.bandwidth ? "center" : "top");
        const clo = labelOffset ?? (anchor === "right" ? marginRight2 : marginLeft2) - 3;
        if (cla === "center") {
          this.textAnchor = void 0;
          this.lineAnchor = anchor === "right" ? "bottom" : "top";
          this.frameAnchor = anchor;
          this.rotate = -90;
        } else {
          this.textAnchor = anchor === "right" ? "end" : "start";
          this.lineAnchor = cla;
          this.frameAnchor = `${cla}-${anchor}`;
          this.rotate = 0;
        }
        this.dy = cla === "top" ? 3 - marginTop2 : cla === "bottom" ? marginBottom2 - 3 : 0;
        this.dx = anchor === "right" ? clo : -clo;
        this.ariaLabel = `${ariaLabel} label`;
        return {
          facets: [[0]],
          channels: { text: { value: [formatAxisLabel(k2, scale3, { anchor, label, labelAnchor: cla, labelArrow })] } }
        };
      })
    ) : null
  );
}
function axisKx(k2, anchor, data, {
  color: color3 = "currentColor",
  opacity: opacity2 = 1,
  stroke = color3,
  strokeOpacity = opacity2,
  strokeWidth = 1,
  fill = color3,
  fillOpacity = opacity2,
  textAnchor,
  textStroke,
  textStrokeOpacity,
  textStrokeWidth,
  tickSize = k2 === "x" ? 6 : 0,
  tickPadding,
  tickRotate,
  y: y3,
  margin,
  marginTop = margin === void 0 ? anchor === "top" ? 30 : 0 : margin,
  marginRight = margin === void 0 ? 20 : margin,
  marginBottom = margin === void 0 ? anchor === "bottom" ? 30 : 0 : margin,
  marginLeft = margin === void 0 ? 20 : margin,
  label,
  labelAnchor,
  labelArrow,
  labelOffset,
  ariaLabel = `${k2}-axis`,
  ...options
}) {
  tickSize = number5(tickSize);
  tickPadding = number5(tickPadding);
  tickRotate = number5(tickRotate);
  if (labelAnchor !== void 0) labelAnchor = keyword(labelAnchor, "labelAnchor", ["center", "left", "right"]);
  labelArrow = maybeLabelArrow(labelArrow);
  return marks(
    tickSize && !isNoneish(stroke) ? axisTickKx(k2, anchor, data, {
      stroke,
      strokeOpacity,
      strokeWidth,
      tickSize,
      tickPadding,
      tickRotate,
      y: y3,
      ariaLabel,
      ...options
    }) : null,
    !isNoneish(fill) ? axisTextKx(k2, anchor, data, {
      fill,
      fillOpacity,
      stroke: textStroke,
      strokeOpacity: textStrokeOpacity,
      strokeWidth: textStrokeWidth,
      textAnchor,
      tickSize,
      tickPadding,
      tickRotate,
      y: y3,
      marginTop,
      marginRight,
      marginBottom,
      marginLeft,
      ariaLabel,
      ...options
    }) : null,
    !isNoneish(fill) && label !== null ? text(
      [],
      labelOptions({ fill, fillOpacity, ...options }, function(data2, facets, channels, scales, dimensions) {
        const scale3 = scales[k2];
        const { marginTop: marginTop2, marginRight: marginRight2, marginBottom: marginBottom2, marginLeft: marginLeft2 } = k2 === "x" && dimensions.inset || dimensions;
        const cla = labelAnchor ?? (scale3.bandwidth ? "center" : "right");
        const clo = labelOffset ?? (anchor === "top" ? marginTop2 : marginBottom2) - 3;
        if (cla === "center") {
          this.frameAnchor = anchor;
          this.textAnchor = void 0;
        } else {
          this.frameAnchor = `${anchor}-${cla}`;
          this.textAnchor = cla === "right" ? "end" : "start";
        }
        this.lineAnchor = anchor;
        this.dy = anchor === "top" ? -clo : clo;
        this.dx = cla === "right" ? marginRight2 - 3 : cla === "left" ? 3 - marginLeft2 : 0;
        this.ariaLabel = `${ariaLabel} label`;
        return {
          facets: [[0]],
          channels: { text: { value: [formatAxisLabel(k2, scale3, { anchor, label, labelAnchor: cla, labelArrow })] } }
        };
      })
    ) : null
  );
}
function axisTickKy(k2, anchor, data, {
  strokeWidth = 1,
  strokeLinecap = null,
  strokeLinejoin = null,
  facetAnchor = anchor + (k2 === "y" ? "-empty" : ""),
  frameAnchor = anchor,
  tickSize,
  inset = 0,
  insetLeft = inset,
  insetRight = inset,
  dx = 0,
  y: y3 = k2 === "y" ? void 0 : null,
  ariaLabel,
  ...options
}) {
  return axisMark(
    vectorY,
    k2,
    data,
    {
      ariaLabel: `${ariaLabel} tick`,
      ariaHidden: true
    },
    {
      strokeWidth,
      strokeLinecap,
      strokeLinejoin,
      facetAnchor,
      frameAnchor,
      y: y3,
      ...options,
      dx: anchor === "left" ? +dx - offset + +insetLeft : +dx + offset - insetRight,
      anchor: "start",
      length: tickSize,
      shape: anchor === "left" ? shapeTickLeft : shapeTickRight
    }
  );
}
function axisTickKx(k2, anchor, data, {
  strokeWidth = 1,
  strokeLinecap = null,
  strokeLinejoin = null,
  facetAnchor = anchor + (k2 === "x" ? "-empty" : ""),
  frameAnchor = anchor,
  tickSize,
  inset = 0,
  insetTop = inset,
  insetBottom = inset,
  dy = 0,
  x: x3 = k2 === "x" ? void 0 : null,
  ariaLabel,
  ...options
}) {
  return axisMark(
    vectorX,
    k2,
    data,
    {
      ariaLabel: `${ariaLabel} tick`,
      ariaHidden: true
    },
    {
      strokeWidth,
      strokeLinejoin,
      strokeLinecap,
      facetAnchor,
      frameAnchor,
      x: x3,
      ...options,
      dy: anchor === "bottom" ? +dy - offset - insetBottom : +dy + offset + +insetTop,
      anchor: "start",
      length: tickSize,
      shape: anchor === "bottom" ? shapeTickBottom : shapeTickTop
    }
  );
}
function axisTextKy(k2, anchor, data, {
  facetAnchor = anchor + (k2 === "y" ? "-empty" : ""),
  frameAnchor = anchor,
  tickSize,
  tickRotate = 0,
  tickPadding = Math.max(3, 9 - tickSize) + (Math.abs(tickRotate) > 60 ? 4 * Math.cos(tickRotate * radians3) : 0),
  text: text2,
  textAnchor = Math.abs(tickRotate) > 60 ? "middle" : anchor === "left" ? "end" : "start",
  lineAnchor = tickRotate > 60 ? "top" : tickRotate < -60 ? "bottom" : "middle",
  fontVariant,
  inset = 0,
  insetLeft = inset,
  insetRight = inset,
  dx = 0,
  ariaLabel,
  y: y3 = k2 === "y" ? void 0 : null,
  ...options
}) {
  return axisMark(
    textY,
    k2,
    data,
    { ariaLabel: `${ariaLabel} tick label` },
    {
      facetAnchor,
      frameAnchor,
      text: text2,
      textAnchor,
      lineAnchor,
      fontVariant,
      rotate: tickRotate,
      y: y3,
      ...options,
      dx: anchor === "left" ? +dx - tickSize - tickPadding + +insetLeft : +dx + +tickSize + +tickPadding - insetRight
    },
    function(scale3, data2, ticks2, tickFormat2, channels) {
      if (fontVariant === void 0) this.fontVariant = inferFontVariant3(scale3);
      if (text2 === void 0) channels.text = inferTextChannel(scale3, data2, ticks2, tickFormat2, anchor);
    }
  );
}
function axisTextKx(k2, anchor, data, {
  facetAnchor = anchor + (k2 === "x" ? "-empty" : ""),
  frameAnchor = anchor,
  tickSize,
  tickRotate = 0,
  tickPadding = Math.max(3, 9 - tickSize) + (Math.abs(tickRotate) >= 10 ? 4 * Math.cos(tickRotate * radians3) : 0),
  text: text2,
  textAnchor = Math.abs(tickRotate) >= 10 ? tickRotate < 0 ^ anchor === "bottom" ? "start" : "end" : "middle",
  lineAnchor = Math.abs(tickRotate) >= 10 ? "middle" : anchor === "bottom" ? "top" : "bottom",
  fontVariant,
  inset = 0,
  insetTop = inset,
  insetBottom = inset,
  dy = 0,
  x: x3 = k2 === "x" ? void 0 : null,
  ariaLabel,
  ...options
}) {
  return axisMark(
    textX,
    k2,
    data,
    { ariaLabel: `${ariaLabel} tick label` },
    {
      facetAnchor,
      frameAnchor,
      text: text2 === void 0 ? null : text2,
      textAnchor,
      lineAnchor,
      fontVariant,
      rotate: tickRotate,
      x: x3,
      ...options,
      dy: anchor === "bottom" ? +dy + +tickSize + +tickPadding - insetBottom : +dy - tickSize - tickPadding + +insetTop
    },
    function(scale3, data2, ticks2, tickFormat2, channels) {
      if (fontVariant === void 0) this.fontVariant = inferFontVariant3(scale3);
      if (text2 === void 0) channels.text = inferTextChannel(scale3, data2, ticks2, tickFormat2, anchor);
    }
  );
}
function gridY() {
  const [data, options] = maybeData(...arguments);
  return gridKy("y", anchorY2(options), data, options);
}
function gridFy() {
  const [data, options] = maybeData(...arguments);
  return gridKy("fy", anchorFy(options), data, options);
}
function gridX() {
  const [data, options] = maybeData(...arguments);
  return gridKx("x", anchorX2(options), data, options);
}
function gridFx() {
  const [data, options] = maybeData(...arguments);
  return gridKx("fx", anchorFx(options), data, options);
}
function gridKy(k2, anchor, data, {
  y: y3 = k2 === "y" ? void 0 : null,
  x: x3 = null,
  x1: x12 = anchor === "left" ? x3 : null,
  x2: x22 = anchor === "right" ? x3 : null,
  ariaLabel = `${k2}-grid`,
  ariaHidden = true,
  ...options
}) {
  return axisMark(ruleY, k2, data, { ariaLabel, ariaHidden }, { y: y3, x1: x12, x2: x22, ...gridDefaults(options) });
}
function gridKx(k2, anchor, data, {
  x: x3 = k2 === "x" ? void 0 : null,
  y: y3 = null,
  y1: y12 = anchor === "top" ? y3 : null,
  y2: y22 = anchor === "bottom" ? y3 : null,
  ariaLabel = `${k2}-grid`,
  ariaHidden = true,
  ...options
}) {
  return axisMark(ruleX, k2, data, { ariaLabel, ariaHidden }, { x: x3, y1: y12, y2: y22, ...gridDefaults(options) });
}
function gridDefaults({
  color: color3 = "currentColor",
  opacity: opacity2 = 0.1,
  stroke = color3,
  strokeOpacity = opacity2,
  strokeWidth = 1,
  ...options
}) {
  return { stroke, strokeOpacity, strokeWidth, ...options };
}
function labelOptions({
  fill,
  fillOpacity,
  fontFamily,
  fontSize,
  fontStyle,
  fontVariant,
  fontWeight,
  monospace,
  pointerEvents,
  shapeRendering,
  clip = false
}, initializer2) {
  [, fill] = maybeColorChannel(fill);
  [, fillOpacity] = maybeNumberChannel(fillOpacity);
  return {
    facet: "super",
    x: null,
    y: null,
    fill,
    fillOpacity,
    fontFamily,
    fontSize,
    fontStyle,
    fontVariant,
    fontWeight,
    monospace,
    pointerEvents,
    shapeRendering,
    clip,
    initializer: initializer2
  };
}
function axisMark(mark, k2, data, properties, options, initialize) {
  let channels;
  function axisInitializer(data2, facets, _channels, scales, dimensions, context) {
    const initializeFacets = data2 == null && (k2 === "fx" || k2 === "fy");
    const { [k2]: scale3 } = scales;
    if (!scale3) throw new Error(`missing scale: ${k2}`);
    const domain = scale3.domain();
    let { interval: interval2, ticks: ticks2, tickFormat: tickFormat2, tickSpacing = k2 === "x" ? 80 : 35 } = options;
    if (typeof ticks2 === "string" && hasTemporalDomain(scale3)) interval2 = ticks2, ticks2 = void 0;
    if (ticks2 === void 0) ticks2 = maybeRangeInterval(interval2, scale3.type) ?? inferTickCount(scale3, tickSpacing);
    if (data2 == null) {
      if (isIterable(ticks2)) {
        data2 = arrayify2(ticks2);
      } else if (isInterval(ticks2)) {
        data2 = inclusiveRange(ticks2, ...extent(domain));
      } else if (scale3.interval) {
        let interval3 = scale3.interval;
        if (scale3.ticks) {
          const [min4, max5] = extent(domain);
          const n = (max5 - min4) / interval3[intervalDuration];
          interval3 = generalizeTimeInterval(interval3, n / ticks2) ?? interval3;
          data2 = inclusiveRange(interval3, min4, max5);
        } else {
          data2 = domain;
          const n = data2.length;
          interval3 = generalizeTimeInterval(interval3, n / ticks2) ?? interval3;
          if (interval3 !== scale3.interval) data2 = inclusiveRange(interval3, ...extent(data2));
        }
        if (interval3 === scale3.interval) {
          const n = Math.round(data2.length / ticks2);
          if (n > 1) data2 = data2.filter((d, i) => i % n === 0);
        }
      } else if (scale3.ticks) {
        data2 = scale3.ticks(ticks2);
      } else {
        data2 = domain;
      }
      if (!scale3.ticks && data2.length && data2 !== domain) {
        const domainSet = new InternSet(domain);
        data2 = data2.filter((d) => domainSet.has(d));
        if (!data2.length) warn(`Warning: the ${k2}-axis ticks appear to not align with the scale domain, resulting in no ticks. Try different ticks?`);
      }
      if (k2 === "y" || k2 === "x") {
        facets = [range2(data2)];
      } else {
        channels[k2] = { scale: k2, value: identity6 };
      }
    }
    initialize == null ? void 0 : initialize.call(this, scale3, data2, ticks2, tickFormat2, channels);
    const initializedChannels = Object.fromEntries(
      Object.entries(channels).map(([name, channel]) => {
        return [name, { ...channel, value: valueof(data2, channel.value) }];
      })
    );
    if (initializeFacets) facets = context.filterFacets(data2, initializedChannels);
    return { data: data2, facets, channels: initializedChannels };
  }
  const basicInitializer = initializer(options).initializer;
  const m = mark(data, initializer({ ...options, initializer: axisInitializer }, basicInitializer));
  if (data == null) {
    channels = m.channels;
    m.channels = {};
  } else {
    channels = {};
  }
  if (properties !== void 0) Object.assign(m, properties);
  if (m.clip === void 0) m.clip = false;
  return m;
}
function inferTickCount(scale3, tickSpacing) {
  const [min4, max5] = extent(scale3.range());
  return (max5 - min4) / tickSpacing;
}
function inferTextChannel(scale3, data, ticks2, tickFormat2, anchor) {
  return { value: inferTickFormat(scale3, data, ticks2, tickFormat2, anchor) };
}
function inferTickFormat(scale3, data, ticks2, tickFormat2, anchor) {
  return typeof tickFormat2 === "function" && !(scale3.type === "log" && scale3.tickFormat) ? tickFormat2 : tickFormat2 === void 0 && data && isTemporal(data) ? inferTimeFormat(scale3.type, data, anchor) ?? formatDefault : scale3.tickFormat ? scale3.tickFormat(typeof ticks2 === "number" ? ticks2 : null, tickFormat2) : typeof tickFormat2 === "string" && scale3.domain().length > 0 ? (isTemporal(scale3.domain()) ? utcFormat : format)(tickFormat2) : tickFormat2 === void 0 ? formatDefault : constant2(tickFormat2);
}
function inclusiveRange(interval2, min4, max5) {
  return interval2.range(min4, interval2.offset(interval2.floor(max5)));
}
var shapeTickBottom = {
  draw(context, l) {
    context.moveTo(0, 0);
    context.lineTo(0, l);
  }
};
var shapeTickTop = {
  draw(context, l) {
    context.moveTo(0, 0);
    context.lineTo(0, -l);
  }
};
var shapeTickLeft = {
  draw(context, l) {
    context.moveTo(0, 0);
    context.lineTo(-l, 0);
  }
};
var shapeTickRight = {
  draw(context, l) {
    context.moveTo(0, 0);
    context.lineTo(l, 0);
  }
};
function inferFontVariant3(scale3) {
  return scale3.bandwidth && !scale3.interval ? void 0 : "tabular-nums";
}
function formatAxisLabel(k2, scale3, { anchor, label = scale3.label, labelAnchor, labelArrow } = {}) {
  if (label == null || label.inferred && hasTemporalDomain(scale3) && /^(date|time|year)$/i.test(label)) return;
  label = String(label);
  if (labelArrow === "auto") labelArrow = (!scale3.bandwidth || scale3.interval) && !/[↑↓→←]/.test(label);
  if (!labelArrow) return label;
  if (labelArrow === true) {
    const order = inferScaleOrder(scale3);
    if (order)
      labelArrow = /x$/.test(k2) || labelAnchor === "center" ? /x$/.test(k2) === order < 0 ? "left" : "right" : order < 0 ? "up" : "down";
  }
  switch (labelArrow) {
    case "left":
      return `← ${label}`;
    case "right":
      return `${label} →`;
    case "up":
      return anchor === "right" ? `${label} ↑` : `↑ ${label}`;
    case "down":
      return anchor === "right" ? `${label} ↓` : `↓ ${label}`;
  }
  return label;
}
function maybeLabelArrow(labelArrow = "auto") {
  return isNoneish(labelArrow) ? false : typeof labelArrow === "boolean" ? labelArrow : keyword(labelArrow, "labelArrow", ["auto", "up", "right", "down", "left"]);
}
function hasTemporalDomain(scale3) {
  return isTemporal(scale3.domain());
}

// node_modules/@observablehq/plot/src/legends/swatches.js
function maybeScale(scale3, key) {
  if (key == null) return key;
  const s2 = scale3(key);
  if (!s2) throw new Error(`scale not found: ${key}`);
  return s2;
}
function legendSwatches(color3, { opacity: opacity2, ...options } = {}) {
  if (!isOrdinalScale(color3) && !isThresholdScale(color3))
    throw new Error(`swatches legend requires ordinal or threshold color scale (not ${color3.type})`);
  return legendItems(
    color3,
    options,
    (selection2, scale3, width, height) => selection2.append("svg").attr("width", width).attr("height", height).attr("fill", scale3.scale).attr("fill-opacity", maybeNumberChannel(opacity2)[1]).append("rect").attr("width", "100%").attr("height", "100%")
  );
}
function legendSymbols(symbol2, {
  fill = ((_a) => (_a = symbol2.hint) == null ? void 0 : _a.fill)() !== void 0 ? symbol2.hint.fill : "none",
  fillOpacity = 1,
  stroke = ((_b) => (_b = symbol2.hint) == null ? void 0 : _b.stroke)() !== void 0 ? symbol2.hint.stroke : isNoneish(fill) ? "currentColor" : "none",
  strokeOpacity = 1,
  strokeWidth = 1.5,
  r = 4.5,
  ...options
} = {}, scale3) {
  const [vf, cf] = maybeColorChannel(fill);
  const [vs, cs] = maybeColorChannel(stroke);
  const sf = maybeScale(scale3, vf);
  const ss = maybeScale(scale3, vs);
  const size = r * r * Math.PI;
  fillOpacity = maybeNumberChannel(fillOpacity)[1];
  strokeOpacity = maybeNumberChannel(strokeOpacity)[1];
  strokeWidth = maybeNumberChannel(strokeWidth)[1];
  return legendItems(
    symbol2,
    options,
    (selection2, scale4, width, height) => selection2.append("svg").attr("viewBox", "-8 -8 16 16").attr("width", width).attr("height", height).attr("fill", vf === "color" ? (d) => sf.scale(d) : cf).attr("fill-opacity", fillOpacity).attr("stroke", vs === "color" ? (d) => ss.scale(d) : cs).attr("stroke-opacity", strokeOpacity).attr("stroke-width", strokeWidth).append("path").attr("d", (d) => {
      const p = pathRound();
      symbol2.scale(d).draw(p, size);
      return p;
    })
  );
}
function legendItems(scale3, options = {}, swatch) {
  let {
    columns,
    tickFormat: tickFormat2,
    fontVariant = inferFontVariant(scale3),
    // TODO label,
    swatchSize = 15,
    swatchWidth = swatchSize,
    swatchHeight = swatchSize,
    marginLeft = 0,
    className,
    style,
    width
  } = options;
  const context = createContext(options);
  className = maybeClassName(className);
  tickFormat2 = inferTickFormat(scale3.scale, scale3.domain, void 0, tickFormat2);
  const swatches = create2("div", context).attr(
    "class",
    `${className}-swatches ${className}-swatches-${columns != null ? "columns" : "wrap"}`
  );
  let extraStyle;
  if (columns != null) {
    extraStyle = `:where(.${className}-swatches-columns .${className}-swatch) {
  display: flex;
  align-items: center;
  break-inside: avoid;
  padding-bottom: 1px;
}
:where(.${className}-swatches-columns .${className}-swatch::before) {
  flex-shrink: 0;
}
:where(.${className}-swatches-columns .${className}-swatch-label) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}`;
    swatches.style("columns", columns).selectAll().data(scale3.domain).enter().append("div").attr("class", `${className}-swatch`).call(swatch, scale3, swatchWidth, swatchHeight).call(
      (item) => item.append("div").attr("class", `${className}-swatch-label`).attr("title", tickFormat2).text(tickFormat2)
    );
  } else {
    extraStyle = `:where(.${className}-swatches-wrap) {
  display: flex;
  align-items: center;
  min-height: 33px;
  flex-wrap: wrap;
}
:where(.${className}-swatches-wrap .${className}-swatch) {
  display: inline-flex;
  align-items: center;
  margin-right: 1em;
}`;
    swatches.selectAll().data(scale3.domain).enter().append("span").attr("class", `${className}-swatch`).call(swatch, scale3, swatchWidth, swatchHeight).append(function() {
      return this.ownerDocument.createTextNode(tickFormat2.apply(this, arguments));
    });
  }
  return swatches.call(
    (div) => div.insert("style", "*").text(
      `:where(.${className}-swatches) {
  font-family: system-ui, sans-serif;
  font-size: 10px;
  margin-bottom: 0.5em;
}
:where(.${className}-swatch > svg) {
  margin-right: 0.5em;
  overflow: visible;
}
${extraStyle}`
    )
  ).style("margin-left", marginLeft ? `${+marginLeft}px` : null).style("width", width === void 0 ? null : `${+width}px`).style("font-variant", impliedString(fontVariant, "normal")).call(applyInlineStyles, style).node();
}

// node_modules/@observablehq/plot/src/legends.js
var legendRegistry = /* @__PURE__ */ new Map([
  ["symbol", legendSymbols],
  ["color", legendColor],
  ["opacity", legendOpacity]
]);
function legend(options = {}) {
  for (const [key, value] of legendRegistry) {
    const scale3 = options[key];
    if (isScaleOptions(scale3)) {
      const context = createContext(options);
      let hint;
      if (key === "symbol") {
        const { fill, stroke = fill === void 0 && isScaleOptions(options.color) ? "color" : void 0 } = options;
        hint = { fill, stroke };
      }
      return value(
        normalizeScale(key, scale3, hint),
        legendOptions(context, scale3, options),
        (key2) => isScaleOptions(options[key2]) ? normalizeScale(key2, options[key2]) : null
      );
    }
  }
  throw new Error("unknown legend type; no scale found");
}
function exposeLegends(scales, context, defaults22 = {}) {
  return (key, options) => {
    if (!legendRegistry.has(key)) throw new Error(`unknown legend type: ${key}`);
    if (!(key in scales)) return;
    return legendRegistry.get(key)(scales[key], legendOptions(context, defaults22[key], options), (key2) => scales[key2]);
  };
}
function legendOptions({ className, ...context }, { label, ticks: ticks2, tickFormat: tickFormat2 } = {}, options) {
  return inherit2(options, { className, ...context }, { label, ticks: ticks2, tickFormat: tickFormat2 });
}
function legendColor(color3, { legend: legend2 = true, ...options }) {
  if (legend2 === true) legend2 = color3.type === "ordinal" ? "swatches" : "ramp";
  if (color3.domain === void 0) return;
  switch (`${legend2}`.toLowerCase()) {
    case "swatches":
      return legendSwatches(color3, options);
    case "ramp":
      return legendRamp(color3, options);
    default:
      throw new Error(`unknown legend type: ${legend2}`);
  }
}
function legendOpacity({ type: type2, interpolate, ...scale3 }, { legend: legend2 = true, color: color3 = rgb(0, 0, 0), ...options }) {
  if (!interpolate) throw new Error(`${type2} opacity scales are not supported`);
  if (legend2 === true) legend2 = "ramp";
  if (`${legend2}`.toLowerCase() !== "ramp") throw new Error(`${legend2} opacity legends are not supported`);
  return legendColor({ type: type2, ...scale3, interpolate: interpolateOpacity(color3) }, { legend: legend2, ...options });
}
function interpolateOpacity(color3) {
  const { r, g, b } = rgb(color3) || rgb(0, 0, 0);
  return (t) => `rgba(${r},${g},${b},${t})`;
}
function createLegends(scales, context, options) {
  const legends = [];
  for (const [key, value] of legendRegistry) {
    const o = options[key];
    if ((o == null ? void 0 : o.legend) && key in scales) {
      const legend2 = value(scales[key], legendOptions(context, scales[key], o), (key2) => scales[key2]);
      if (legend2 != null) legends.push(legend2);
    }
  }
  return legends;
}

// node_modules/@observablehq/plot/src/transforms/identity.js
function maybeIdentityX(options = {}, k2 = "x") {
  return hasX(options) ? options : { ...options, [k2]: identity6 };
}
function maybeIdentityY(options = {}, k2 = "y") {
  return hasY(options) ? options : { ...options, [k2]: identity6 };
}

// node_modules/@observablehq/plot/src/transforms/exclusiveFacets.js
function exclusiveFacets(data, facets) {
  if (facets.length === 1) return { data, facets };
  const n = lengthof(data);
  const O = new Uint8Array(n);
  let overlaps = 0;
  for (const facet of facets) {
    for (const i of facet) {
      if (O[i]) ++overlaps;
      O[i] = 1;
    }
  }
  if (overlaps === 0) return { data, facets };
  data = slice5(data);
  const R = data[reindex] = new Uint32Array(n + overlaps);
  facets = facets.map((facet) => slice5(facet, Uint32Array));
  let j = n;
  O.fill(0);
  for (const facet of facets) {
    for (let k2 = 0, m = facet.length; k2 < m; ++k2) {
      const i = facet[k2];
      if (O[i]) facet[k2] = j, data[j] = data[i], R[j] = i, ++j;
      else R[i] = i;
      O[i] = 1;
    }
  }
  return { data, facets };
}

// node_modules/@observablehq/plot/src/transforms/stack.js
function stackX(stackOptions = {}, options = {}) {
  if (arguments.length === 1) [stackOptions, options] = mergeOptions(stackOptions);
  const { y1: y12, y: y3 = y12, x: x3, ...rest } = options;
  const [transform2, Y3, x12, x22] = stack(y3, x3, "y", "x", stackOptions, rest);
  return { ...transform2, y1: y12, y: Y3, x1: x12, x2: x22, x: mid(x12, x22) };
}
function stackX1(stackOptions = {}, options = {}) {
  if (arguments.length === 1) [stackOptions, options] = mergeOptions(stackOptions);
  const { y1: y12, y: y3 = y12, x: x3 } = options;
  const [transform2, Y3, X3] = stack(y3, x3, "y", "x", stackOptions, options);
  return { ...transform2, y1: y12, y: Y3, x: X3 };
}
function stackX2(stackOptions = {}, options = {}) {
  if (arguments.length === 1) [stackOptions, options] = mergeOptions(stackOptions);
  const { y1: y12, y: y3 = y12, x: x3 } = options;
  const [transform2, Y3, , X3] = stack(y3, x3, "y", "x", stackOptions, options);
  return { ...transform2, y1: y12, y: Y3, x: X3 };
}
function stackY(stackOptions = {}, options = {}) {
  if (arguments.length === 1) [stackOptions, options] = mergeOptions(stackOptions);
  const { x1: x12, x: x3 = x12, y: y3, ...rest } = options;
  const [transform2, X3, y12, y22] = stack(x3, y3, "x", "y", stackOptions, rest);
  return { ...transform2, x1: x12, x: X3, y1: y12, y2: y22, y: mid(y12, y22) };
}
function stackY1(stackOptions = {}, options = {}) {
  if (arguments.length === 1) [stackOptions, options] = mergeOptions(stackOptions);
  const { x1: x12, x: x3 = x12, y: y3 } = options;
  const [transform2, X3, Y3] = stack(x3, y3, "x", "y", stackOptions, options);
  return { ...transform2, x1: x12, x: X3, y: Y3 };
}
function stackY2(stackOptions = {}, options = {}) {
  if (arguments.length === 1) [stackOptions, options] = mergeOptions(stackOptions);
  const { x1: x12, x: x3 = x12, y: y3 } = options;
  const [transform2, X3, , Y3] = stack(x3, y3, "x", "y", stackOptions, options);
  return { ...transform2, x1: x12, x: X3, y: Y3 };
}
function maybeStackX({ x: x3, x1: x12, x2: x22, ...options } = {}) {
  options = withTip(options, "y");
  if (x12 === void 0 && x22 === void 0) return stackX({ x: x3, ...options });
  [x12, x22] = maybeZero(x3, x12, x22);
  return { ...options, x1: x12, x2: x22 };
}
function maybeStackY({ y: y3, y1: y12, y2: y22, ...options } = {}) {
  options = withTip(options, "x");
  if (y12 === void 0 && y22 === void 0) return stackY({ y: y3, ...options });
  [y12, y22] = maybeZero(y3, y12, y22);
  return { ...options, y1: y12, y2: y22 };
}
function mergeOptions(options) {
  const { offset: offset2, order, reverse: reverse3, ...rest } = options;
  return [{ offset: offset2, order, reverse: reverse3 }, rest];
}
var lengthy = { length: true };
function stack(x3, y3 = one2, kx2, ky2, { offset: offset2, order, reverse: reverse3 }, options) {
  if (y3 === null) throw new Error(`stack requires ${ky2}`);
  const z = maybeZ(options);
  const [X3, setX] = maybeColumn(x3);
  const [Y13, setY1] = column(y3);
  const [Y23, setY2] = column(y3);
  Y13.hint = Y23.hint = lengthy;
  offset2 = maybeOffset(offset2);
  order = maybeOrder2(order, offset2, ky2);
  return [
    basic(options, (data, facets, plotOptions) => {
      ({ data, facets } = exclusiveFacets(data, facets));
      const X4 = x3 == null ? void 0 : setX(maybeApplyInterval(valueof(data, x3), plotOptions == null ? void 0 : plotOptions[kx2]));
      const Y3 = valueof(data, y3, Float64Array);
      const Z = valueof(data, z);
      const compare = order && order(data, X4, Y3, Z);
      const n = lengthof(data);
      const Y14 = setY1(new Float64Array(n));
      const Y24 = setY2(new Float64Array(n));
      const facetstacks = [];
      for (const facet of facets) {
        const stacks = X4 ? Array.from(group(facet, (i) => X4[i]).values()) : [facet];
        if (compare) for (const stack2 of stacks) stack2.sort(compare);
        for (const stack2 of stacks) {
          let yn = 0;
          let yp = 0;
          if (reverse3) stack2.reverse();
          for (const i of stack2) {
            const y4 = Y3[i];
            if (y4 < 0) yn = Y24[i] = (Y14[i] = yn) + y4;
            else if (y4 > 0) yp = Y24[i] = (Y14[i] = yp) + y4;
            else Y24[i] = Y14[i] = yp;
          }
        }
        facetstacks.push(stacks);
      }
      if (offset2) offset2(facetstacks, Y14, Y24, Z);
      return { data, facets };
    }),
    X3,
    Y13,
    Y23
  ];
}
function maybeOffset(offset2) {
  if (offset2 == null) return;
  if (typeof offset2 === "function") return offset2;
  switch (`${offset2}`.toLowerCase()) {
    case "expand":
    case "normalize":
      return offsetExpand;
    case "center":
    case "silhouette":
      return offsetCenter;
    case "wiggle":
      return offsetWiggle;
  }
  throw new Error(`unknown offset: ${offset2}`);
}
function extent2(stack2, Y23) {
  let min4 = 0, max5 = 0;
  for (const i of stack2) {
    const y3 = Y23[i];
    if (y3 < min4) min4 = y3;
    if (y3 > max5) max5 = y3;
  }
  return [min4, max5];
}
function offsetExpand(facetstacks, Y13, Y23) {
  for (const stacks of facetstacks) {
    for (const stack2 of stacks) {
      const [yn, yp] = extent2(stack2, Y23);
      for (const i of stack2) {
        const m = 1 / (yp - yn || 1);
        Y13[i] = m * (Y13[i] - yn);
        Y23[i] = m * (Y23[i] - yn);
      }
    }
  }
}
function offsetCenter(facetstacks, Y13, Y23) {
  for (const stacks of facetstacks) {
    for (const stack2 of stacks) {
      const [yn, yp] = extent2(stack2, Y23);
      for (const i of stack2) {
        const m = (yp + yn) / 2;
        Y13[i] -= m;
        Y23[i] -= m;
      }
    }
    offsetZero(stacks, Y13, Y23);
  }
  offsetCenterFacets(facetstacks, Y13, Y23);
}
function offsetWiggle(facetstacks, Y13, Y23, Z) {
  for (const stacks of facetstacks) {
    const prev = new InternMap();
    let y3 = 0;
    for (const stack2 of stacks) {
      let j = -1;
      const Fi = stack2.map((i) => Math.abs(Y23[i] - Y13[i]));
      const Df = stack2.map((i) => {
        j = Z ? Z[i] : ++j;
        const value = Y23[i] - Y13[i];
        const diff = prev.has(j) ? value - prev.get(j) : 0;
        prev.set(j, value);
        return diff;
      });
      const Cf1 = [0, ...cumsum(Df)];
      for (const i of stack2) {
        Y13[i] += y3;
        Y23[i] += y3;
      }
      const s1 = sum(Fi);
      if (s1) y3 -= sum(Fi, (d, i) => (Df[i] / 2 + Cf1[i]) * d) / s1;
    }
    offsetZero(stacks, Y13, Y23);
  }
  offsetCenterFacets(facetstacks, Y13, Y23);
}
function offsetZero(stacks, Y13, Y23) {
  const m = min(stacks, (stack2) => min(stack2, (i) => Y13[i]));
  for (const stack2 of stacks) {
    for (const i of stack2) {
      Y13[i] -= m;
      Y23[i] -= m;
    }
  }
}
function offsetCenterFacets(facetstacks, Y13, Y23) {
  const n = facetstacks.length;
  if (n === 1) return;
  const facets = facetstacks.map((stacks) => stacks.flat());
  const m = facets.map((I) => (min(I, (i) => Y13[i]) + max(I, (i) => Y23[i])) / 2);
  const m0 = min(m);
  for (let j = 0; j < n; j++) {
    const p = m0 - m[j];
    for (const i of facets[j]) {
      Y13[i] += p;
      Y23[i] += p;
    }
  }
}
function maybeOrder2(order, offset2, ky2) {
  if (order === void 0 && offset2 === offsetWiggle) return orderInsideOut(ascendingDefined2);
  if (order == null) return;
  if (typeof order === "string") {
    const negate2 = order.startsWith("-");
    const compare = negate2 ? descendingDefined : ascendingDefined2;
    switch ((negate2 ? order.slice(1) : order).toLowerCase()) {
      case "value":
      case ky2:
        return orderY(compare);
      case "z":
        return orderZ(compare);
      case "sum":
        return orderSum(compare);
      case "appearance":
        return orderAppearance(compare);
      case "inside-out":
        return orderInsideOut(compare);
    }
    return orderAccessor(field(order));
  }
  if (typeof order === "function") return (order.length === 1 ? orderAccessor : orderComparator)(order);
  if (isArray(order)) return orderGiven(order);
  throw new Error(`invalid order: ${order}`);
}
function orderY(compare) {
  return (data, X3, Y3) => (i, j) => compare(Y3[i], Y3[j]);
}
function orderZ(compare) {
  return (data, X3, Y3, Z) => (i, j) => compare(Z[i], Z[j]);
}
function orderSum(compare) {
  return orderZDomain(
    compare,
    (data, X3, Y3, Z) => groupSort(
      range2(data),
      (I) => sum(I, (i) => Y3[i]),
      (i) => Z[i]
    )
  );
}
function orderAppearance(compare) {
  return orderZDomain(
    compare,
    (data, X3, Y3, Z) => groupSort(
      range2(data),
      (I) => X3[greatest(I, (i) => Y3[i])],
      (i) => Z[i]
    )
  );
}
function orderInsideOut(compare) {
  return orderZDomain(compare, (data, X3, Y3, Z) => {
    const I = range2(data);
    const K2 = groupSort(
      I,
      (I2) => X3[greatest(I2, (i) => Y3[i])],
      (i) => Z[i]
    );
    const sums = rollup(
      I,
      (I2) => sum(I2, (i) => Y3[i]),
      (i) => Z[i]
    );
    const Kp = [], Kn = [];
    let s2 = 0;
    for (const k2 of K2) {
      if (s2 < 0) {
        s2 += sums.get(k2);
        Kp.push(k2);
      } else {
        s2 -= sums.get(k2);
        Kn.push(k2);
      }
    }
    return Kn.reverse().concat(Kp);
  });
}
function orderAccessor(f) {
  return (data) => {
    const O = valueof(data, f);
    return (i, j) => ascendingDefined2(O[i], O[j]);
  };
}
function orderComparator(f) {
  return (data) => {
    return isArray(data) ? (i, j) => f(data[i], data[j]) : (i, j) => f(data.get(i), data.get(j));
  };
}
function orderGiven(domain) {
  return orderZDomain(ascendingDefined2, () => domain);
}
function orderZDomain(compare, domain) {
  return (data, X3, Y3, Z) => {
    if (!Z) throw new Error("missing channel: z");
    const map6 = new InternMap(domain(data, X3, Y3, Z).map((d, i) => [d, i]));
    return (i, j) => compare(map6.get(Z[i]), map6.get(Z[j]));
  };
}

// node_modules/@observablehq/plot/src/marks/rect.js
var defaults4 = {
  ariaLabel: "rect"
};
var Rect = class extends Mark {
  constructor(data, options = {}) {
    const { x1: x12, y1: y12, x2: x22, y2: y22 } = options;
    super(
      data,
      {
        x1: { value: x12, scale: "x", type: x12 != null && x22 == null ? "band" : void 0, optional: true },
        y1: { value: y12, scale: "y", type: y12 != null && y22 == null ? "band" : void 0, optional: true },
        x2: { value: x22, scale: "x", optional: true },
        y2: { value: y22, scale: "y", optional: true }
      },
      options,
      defaults4
    );
    rectInsets(this, options);
    rectRadii(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    let { x1: X13, y1: Y13, x2: X23, y2: Y23 } = channels;
    const { marginTop, marginRight, marginBottom, marginLeft, width, height } = dimensions;
    const { projection: projection3 } = context;
    const { insetTop, insetRight, insetBottom, insetLeft } = this;
    const { rx, ry, rx1y1, rx1y2, rx2y1, rx2y2 } = this;
    if ((X13 || X23) && !projection3 && isCollapsed(x3)) X13 = X23 = null;
    if ((Y13 || Y23) && !projection3 && isCollapsed(y3)) Y13 = Y23 = null;
    const bx = (x3 == null ? void 0 : x3.bandwidth) ? x3.bandwidth() : 0;
    const by = (y3 == null ? void 0 : y3.bandwidth) ? y3.bandwidth() : 0;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, {}, 0, 0).call(
      (g) => g.selectAll().data(index2).enter().call(
        rx1y1 || rx1y2 || rx2y1 || rx2y2 ? (g2) => g2.append("path").call(applyDirectStyles, this).call(
          applyRoundedRect,
          X13 && X23 ? (i) => X13[i] + (X23[i] < X13[i] ? -insetRight : insetLeft) : X13 ? (i) => X13[i] + insetLeft : marginLeft + insetLeft,
          Y13 && Y23 ? (i) => Y13[i] + (Y23[i] < Y13[i] ? -insetBottom : insetTop) : Y13 ? (i) => Y13[i] + insetTop : marginTop + insetTop,
          X13 && X23 ? (i) => X23[i] - (X23[i] < X13[i] ? -insetLeft : insetRight) : X13 ? (i) => X13[i] + bx - insetRight : width - marginRight - insetRight,
          Y13 && Y23 ? (i) => Y23[i] - (Y23[i] < Y13[i] ? -insetTop : insetBottom) : Y13 ? (i) => Y13[i] + by - insetBottom : height - marginBottom - insetBottom,
          this
        ).call(applyChannelStyles, this, channels) : (g2) => g2.append("rect").call(applyDirectStyles, this).attr(
          "x",
          X13 ? X23 ? (i) => Math.min(X13[i], X23[i]) + insetLeft : (i) => X13[i] + insetLeft : marginLeft + insetLeft
        ).attr(
          "y",
          Y13 ? Y23 ? (i) => Math.min(Y13[i], Y23[i]) + insetTop : (i) => Y13[i] + insetTop : marginTop + insetTop
        ).attr(
          "width",
          X13 ? X23 ? (i) => Math.max(0, Math.abs(X23[i] - X13[i]) + bx - insetLeft - insetRight) : bx - insetLeft - insetRight : width - marginRight - marginLeft - insetRight - insetLeft
        ).attr(
          "height",
          Y13 ? Y23 ? (i) => Math.max(0, Math.abs(Y13[i] - Y23[i]) + by - insetTop - insetBottom) : by - insetTop - insetBottom : height - marginTop - marginBottom - insetTop - insetBottom
        ).call(applyAttr, "rx", rx).call(applyAttr, "ry", ry).call(applyChannelStyles, this, channels)
      )
    ).node();
  }
};
function rectInsets(mark, { inset = 0, insetTop = inset, insetRight = inset, insetBottom = inset, insetLeft = inset } = {}) {
  mark.insetTop = number5(insetTop);
  mark.insetRight = number5(insetRight);
  mark.insetBottom = number5(insetBottom);
  mark.insetLeft = number5(insetLeft);
}
function rectRadii(mark, {
  r,
  rx,
  // for elliptic corners
  ry,
  // for elliptic corners
  rx1 = r,
  ry1 = r,
  rx2 = r,
  ry2 = r,
  rx1y1 = rx1 !== void 0 ? +rx1 : ry1 !== void 0 ? +ry1 : 0,
  rx1y2 = rx1 !== void 0 ? +rx1 : ry2 !== void 0 ? +ry2 : 0,
  rx2y1 = rx2 !== void 0 ? +rx2 : ry1 !== void 0 ? +ry1 : 0,
  rx2y2 = rx2 !== void 0 ? +rx2 : ry2 !== void 0 ? +ry2 : 0
} = {}) {
  if (rx1y1 || rx1y2 || rx2y1 || rx2y2) {
    mark.rx1y1 = rx1y1;
    mark.rx1y2 = rx1y2;
    mark.rx2y1 = rx2y1;
    mark.rx2y2 = rx2y2;
  } else {
    mark.rx = impliedString(rx, "auto");
    mark.ry = impliedString(ry, "auto");
  }
}
function applyRoundedRect(selection2, X13, Y13, X23, Y23, mark) {
  const { rx1y1: r11, rx1y2: r12, rx2y1: r21, rx2y2: r22 } = mark;
  if (typeof X13 !== "function") X13 = constant2(X13);
  if (typeof Y13 !== "function") Y13 = constant2(Y13);
  if (typeof X23 !== "function") X23 = constant2(X23);
  if (typeof Y23 !== "function") Y23 = constant2(Y23);
  const rx = Math.max(Math.abs(r11 + r21), Math.abs(r12 + r22));
  const ry = Math.max(Math.abs(r11 + r12), Math.abs(r21 + r22));
  selection2.attr("d", (i) => {
    const x12 = X13(i);
    const y12 = Y13(i);
    const x22 = X23(i);
    const y22 = Y23(i);
    const ix = x12 > x22;
    const iy = y12 > y22;
    const l = ix ? x22 : x12;
    const r = ix ? x12 : x22;
    const t = iy ? y22 : y12;
    const b = iy ? y12 : y22;
    const k2 = Math.min(1, (r - l) / rx, (b - t) / ry);
    const tl = k2 * (ix ? iy ? r22 : r21 : iy ? r12 : r11);
    const tr = k2 * (ix ? iy ? r12 : r11 : iy ? r22 : r21);
    const br = k2 * (ix ? iy ? r11 : r12 : iy ? r21 : r22);
    const bl = k2 * (ix ? iy ? r21 : r22 : iy ? r11 : r12);
    return `M${l},${t + biasY(tl, bl)}A${tl},${tl} 0 0 ${tl < 0 ? 0 : 1} ${l + biasX(tl, bl)},${t}H${r - biasX(tr, br)}A${tr},${tr} 0 0 ${tr < 0 ? 0 : 1} ${r},${t + biasY(tr, br)}V${b - biasY(br, tr)}A${br},${br} 0 0 ${br < 0 ? 0 : 1} ${r - biasX(br, tr)},${b}H${l + biasX(bl, tl)}A${bl},${bl} 0 0 ${bl < 0 ? 0 : 1} ${l},${b - biasY(bl, tl)}Z`;
  });
}
function biasX(r1, r2) {
  return r2 < 0 ? r1 : Math.abs(r1);
}
function biasY(r1, r2) {
  return r2 < 0 ? Math.abs(r1) : r1;
}
function rect(data, options) {
  return new Rect(data, maybeTrivialIntervalX(maybeTrivialIntervalY(options)));
}
function rectX(data, options = {}) {
  if (!hasXY(options)) options = { ...options, y: indexOf, x2: identity6, interval: 1 };
  return new Rect(data, maybeStackX(maybeTrivialIntervalY(maybeIdentityX(options))));
}
function rectY(data, options = {}) {
  if (!hasXY(options)) options = { ...options, x: indexOf, y2: identity6, interval: 1 };
  return new Rect(data, maybeStackY(maybeTrivialIntervalX(maybeIdentityY(options))));
}

// node_modules/@observablehq/plot/src/marks/frame.js
var defaults5 = {
  ariaLabel: "frame",
  fill: "none",
  stroke: "currentColor",
  clip: false
};
var lineDefaults = {
  ariaLabel: "frame",
  fill: null,
  stroke: "currentColor",
  strokeLinecap: "square",
  clip: false
};
var Frame = class extends Mark {
  constructor(options = {}) {
    const { anchor = null } = options;
    super(singleton, void 0, options, anchor == null ? defaults5 : lineDefaults);
    this.anchor = maybeKeyword(anchor, "anchor", ["top", "right", "bottom", "left"]);
    rectInsets(this, options);
    if (!anchor) rectRadii(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    const { marginTop, marginRight, marginBottom, marginLeft, width, height } = dimensions;
    const { anchor, insetTop, insetRight, insetBottom, insetLeft } = this;
    const { rx, ry, rx1y1, rx1y2, rx2y1, rx2y2 } = this;
    const x12 = marginLeft + insetLeft;
    const x22 = width - marginRight - insetRight;
    const y12 = marginTop + insetTop;
    const y22 = height - marginBottom - insetBottom;
    return create2(anchor ? "svg:line" : rx1y1 || rx1y2 || rx2y1 || rx2y2 ? "svg:path" : "svg:rect", context).datum(0).call(applyIndirectStyles, this, dimensions, context).call(applyDirectStyles, this).call(applyChannelStyles, this, channels).call(applyTransform, this, {}).call(
      anchor === "left" ? (line2) => line2.attr("x1", x12).attr("x2", x12).attr("y1", y12).attr("y2", y22) : anchor === "right" ? (line2) => line2.attr("x1", x22).attr("x2", x22).attr("y1", y12).attr("y2", y22) : anchor === "top" ? (line2) => line2.attr("x1", x12).attr("x2", x22).attr("y1", y12).attr("y2", y12) : anchor === "bottom" ? (line2) => line2.attr("x1", x12).attr("x2", x22).attr("y1", y22).attr("y2", y22) : rx1y1 || rx1y2 || rx2y1 || rx2y2 ? (path2) => path2.call(applyRoundedRect, x12, y12, x22, y22, this) : (rect2) => rect2.attr("x", x12).attr("y", y12).attr("width", x22 - x12).attr("height", y22 - y12).attr("rx", rx).attr("ry", ry)
    ).node();
  }
};
function frame2(options) {
  return new Frame(options);
}

// node_modules/@observablehq/plot/src/marks/tip.js
var defaults6 = {
  ariaLabel: "tip",
  fill: "var(--plot-background)",
  stroke: "currentColor"
};
var ignoreChannels = /* @__PURE__ */ new Set(["geometry", "href", "src", "ariaLabel", "scales"]);
var Tip = class extends Mark {
  constructor(data, options = {}) {
    if (options.tip) options = { ...options, tip: false };
    if (options.title === void 0 && isIterable(data) && isTextual(data)) options = { ...options, title: identity6 };
    const {
      x: x3,
      y: y3,
      x1: x12,
      x2: x22,
      y1: y12,
      y2: y22,
      anchor,
      preferredAnchor = "bottom",
      monospace,
      fontFamily = monospace ? "ui-monospace, monospace" : void 0,
      fontSize,
      fontStyle,
      fontVariant,
      fontWeight,
      lineHeight = 1,
      lineWidth = 20,
      frameAnchor,
      format: format3,
      textAnchor = "start",
      textOverflow,
      textPadding = 8,
      title,
      pointerSize = 12,
      pathFilter = "drop-shadow(0 3px 4px rgba(0,0,0,0.2))"
    } = options;
    super(
      data,
      {
        x: { value: x12 != null && x22 != null ? null : x3, scale: "x", optional: true },
        // ignore midpoint
        y: { value: y12 != null && y22 != null ? null : y3, scale: "y", optional: true },
        // ignore midpoint
        x1: { value: x12, scale: "x", optional: x22 == null },
        y1: { value: y12, scale: "y", optional: y22 == null },
        x2: { value: x22, scale: "x", optional: x12 == null },
        y2: { value: y22, scale: "y", optional: y12 == null },
        title: { value: title, optional: true }
        // filter: defined
      },
      options,
      defaults6
    );
    this.anchor = maybeAnchor(anchor, "anchor");
    this.preferredAnchor = maybeAnchor(preferredAnchor, "preferredAnchor");
    this.frameAnchor = maybeFrameAnchor(frameAnchor);
    this.textAnchor = impliedString(textAnchor, "middle");
    this.textPadding = +textPadding;
    this.pointerSize = +pointerSize;
    this.pathFilter = string(pathFilter);
    this.lineHeight = +lineHeight;
    this.lineWidth = +lineWidth;
    this.textOverflow = maybeTextOverflow(textOverflow);
    this.monospace = !!monospace;
    this.fontFamily = string(fontFamily);
    this.fontSize = number5(fontSize);
    this.fontStyle = string(fontStyle);
    this.fontVariant = string(fontVariant);
    this.fontWeight = string(fontWeight);
    for (const key in defaults6) if (key in this.channels) this[key] = defaults6[key];
    this.splitLines = splitter2(this);
    this.clipLine = clipper(this);
    this.format = typeof format3 === "string" || typeof format3 === "function" ? { title: format3 } : { ...format3 };
  }
  render(index2, scales, values2, dimensions, context) {
    const mark = this;
    const { x: x3, y: y3, fx, fy } = scales;
    const { ownerSVGElement: svg2, document: document2 } = context;
    const { anchor, monospace, lineHeight, lineWidth } = this;
    const { textPadding: r, pointerSize: m, pathFilter } = this;
    const { marginTop, marginLeft } = dimensions;
    const { x1: X13, y1: Y13, x2: X23, y2: Y23, x: X3 = X13 ?? X23, y: Y3 = Y13 ?? Y23 } = values2;
    const ox2 = fx ? fx(index2.fx) - marginLeft : 0;
    const oy2 = fy ? fy(index2.fy) - marginTop : 0;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    const px = anchorX(values2, cx);
    const py = anchorY(values2, cy);
    const widthof = monospace ? monospaceWidth : defaultWidth;
    const ee = widthof(ellipsis);
    let sources, format3;
    if ("title" in values2) {
      sources = getSourceChannels.call(this, { title: values2.channels.title }, scales);
      format3 = formatTitle;
    } else {
      sources = getSourceChannels.call(this, values2.channels, scales);
      format3 = formatChannels;
    }
    const g = create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyIndirectTextStyles, this).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      (g2) => g2.selectAll().data(index2).enter().append("g").attr("transform", (i) => `translate(${Math.round(px(i))},${Math.round(py(i))})`).call(applyDirectStyles, this).call((g3) => g3.append("path").attr("filter", pathFilter)).call(
        (g3) => g3.append("text").each(function(i) {
          const that = select_default2(this);
          this.setAttribute("fill", "currentColor");
          this.setAttribute("fill-opacity", 1);
          this.setAttribute("stroke", "none");
          const lines = format3.call(mark, i, index2, sources, scales, values2);
          if (typeof lines === "string") {
            for (const line2 of mark.splitLines(lines)) {
              renderLine(that, { value: mark.clipLine(line2) });
            }
          } else {
            const labels = /* @__PURE__ */ new Set();
            for (const line2 of lines) {
              const { label = "" } = line2;
              if (label && labels.has(label)) continue;
              else labels.add(label);
              renderLine(that, line2);
            }
          }
        })
      )
    );
    function renderLine(selection2, { label, value, color: color3, opacity: opacity2 }) {
      label ?? (label = ""), value ?? (value = "");
      const swatch = color3 != null || opacity2 != null;
      let title;
      let w = lineWidth * 100;
      const [j] = cut(label, w, widthof, ee);
      if (j >= 0) {
        label = label.slice(0, j).trimEnd() + ellipsis;
        title = value.trim();
        value = "";
      } else {
        if (label || !value && !swatch) value = " " + value;
        const [k2] = cut(value, w - widthof(label), widthof, ee);
        if (k2 >= 0) {
          title = value.trim();
          value = value.slice(0, k2).trimEnd() + ellipsis;
        }
      }
      const line2 = selection2.append("tspan").attr("x", 0).attr("dy", `${lineHeight}em`).text("​");
      if (label) line2.append("tspan").attr("font-weight", "bold").text(label);
      if (value) line2.append(() => document2.createTextNode(value));
      if (swatch) line2.append("tspan").text(" ■").attr("fill", color3).attr("fill-opacity", opacity2).style("user-select", "none");
      if (title) line2.append("title").text(title);
    }
    function postrender() {
      const { width, height } = dimensions.facet ?? dimensions;
      g.selectChildren().each(function(i) {
        let { x: tx, width: w, height: h } = this.getBBox();
        w = Math.round(w), h = Math.round(h);
        let a2 = anchor;
        if (a2 === void 0) {
          const x4 = px(i) + ox2;
          const y4 = py(i) + oy2;
          const fitLeft = x4 + w + m + r * 2 < width;
          const fitRight = x4 - w - m - r * 2 > 0;
          const fitTop = y4 + h + m + r * 2 < height;
          const fitBottom = y4 - h - m - r * 2 > 0;
          a2 = fitLeft && fitRight ? fitTop && fitBottom ? mark.preferredAnchor : fitBottom ? "bottom" : "top" : fitTop && fitBottom ? fitLeft ? "left" : "right" : (fitLeft || fitRight) && (fitTop || fitBottom) ? `${fitBottom ? "bottom" : "top"}-${fitLeft ? "left" : "right"}` : mark.preferredAnchor;
        }
        const path2 = this.firstChild;
        const text2 = this.lastChild;
        path2.setAttribute("d", getPath(a2, m, r, w, h));
        if (tx) for (const t of text2.childNodes) t.setAttribute("x", -tx);
        text2.setAttribute("y", `${+getLineOffset(a2, text2.childNodes.length, lineHeight).toFixed(6)}em`);
        text2.setAttribute("transform", `translate(${getTextTranslate(a2, m, r, w, h)})`);
      });
      g.attr("visibility", null);
    }
    if (index2.length) {
      g.attr("visibility", "hidden");
      if (svg2.isConnected) Promise.resolve().then(postrender);
      else if (typeof requestAnimationFrame !== "undefined") requestAnimationFrame(postrender);
    }
    return g.node();
  }
};
function tip(data, { x: x3, y: y3, ...options } = {}) {
  if (options.frameAnchor === void 0) [x3, y3] = maybeTuple(x3, y3);
  return new Tip(data, { ...options, x: x3, y: y3 });
}
function getLineOffset(anchor, length3, lineHeight) {
  return /^top(?:-|$)/.test(anchor) ? 0.94 - lineHeight : /^bottom(?:-|$)/ ? -0.29 - length3 * lineHeight : length3 / 2 * lineHeight;
}
function getTextTranslate(anchor, m, r, width, height) {
  switch (anchor) {
    case "middle":
      return [-width / 2, height / 2];
    case "top-left":
      return [r, m + r];
    case "top":
      return [-width / 2, m / 2 + r];
    case "top-right":
      return [-width - r, m + r];
    case "right":
      return [-m / 2 - width - r, height / 2];
    case "bottom-left":
      return [r, -m - r];
    case "bottom":
      return [-width / 2, -m / 2 - r];
    case "bottom-right":
      return [-width - r, -m - r];
    case "left":
      return [r + m / 2, height / 2];
  }
}
function getPath(anchor, m, r, width, height) {
  const w = width + r * 2;
  const h = height + r * 2;
  switch (anchor) {
    case "middle":
      return `M${-w / 2},${-h / 2}h${w}v${h}h${-w}z`;
    case "top-left":
      return `M0,0l${m},${m}h${w - m}v${h}h${-w}z`;
    case "top":
      return `M0,0l${m / 2},${m / 2}h${(w - m) / 2}v${h}h${-w}v${-h}h${(w - m) / 2}z`;
    case "top-right":
      return `M0,0l${-m},${m}h${m - w}v${h}h${w}z`;
    case "right":
      return `M0,0l${-m / 2},${-m / 2}v${m / 2 - h / 2}h${-w}v${h}h${w}v${m / 2 - h / 2}z`;
    case "bottom-left":
      return `M0,0l${m},${-m}h${w - m}v${-h}h${-w}z`;
    case "bottom":
      return `M0,0l${m / 2},${-m / 2}h${(w - m) / 2}v${-h}h${-w}v${h}h${(w - m) / 2}z`;
    case "bottom-right":
      return `M0,0l${-m},${-m}h${m - w}v${-h}h${w}z`;
    case "left":
      return `M0,0l${m / 2},${-m / 2}v${m / 2 - h / 2}h${w}v${h}h${-w}v${m / 2 - h / 2}z`;
  }
}
function getSourceChannels(channels, scales) {
  var _a, _b;
  const sources = {};
  let format3 = this.format;
  format3 = maybeExpandPairedFormat(format3, channels, "x");
  format3 = maybeExpandPairedFormat(format3, channels, "y");
  this.format = format3;
  for (const key in format3) {
    const value = format3[key];
    if (value === null || value === false) {
      continue;
    } else if (key === "fx" || key === "fy") {
      sources[key] = true;
    } else {
      const source = getSource(channels, key);
      if (source) sources[key] = source;
    }
  }
  for (const key in channels) {
    if (key in sources || key in format3 || ignoreChannels.has(key)) continue;
    if ((key === "x" || key === "y") && channels.geometry) continue;
    const source = getSource(channels, key);
    if (source) {
      if (source.scale == null && source.defaultScale === "color") continue;
      sources[key] = source;
    }
  }
  if (this.facet) {
    if (scales.fx && !("fx" in format3)) sources.fx = true;
    if (scales.fy && !("fy" in format3)) sources.fy = true;
  }
  for (const key in sources) {
    const format4 = this.format[key];
    if (typeof format4 === "string") {
      const value = ((_a = sources[key]) == null ? void 0 : _a.value) ?? ((_b = scales[key]) == null ? void 0 : _b.domain()) ?? [];
      this.format[key] = (isTemporal(value) ? utcFormat : format)(format4);
    } else if (format4 === void 0 || format4 === true) {
      const scale3 = scales[key];
      this.format[key] = (scale3 == null ? void 0 : scale3.bandwidth) ? inferTickFormat(scale3, scale3.domain()) : formatDefault;
    }
  }
  return sources;
}
function maybeExpandPairedFormat(format3, channels, key) {
  if (!(key in format3)) return format3;
  const key1 = `${key}1`;
  const key2 = `${key}2`;
  if ((key1 in format3 || !(key1 in channels)) && (key2 in format3 || !(key2 in channels))) return format3;
  const entries = Object.entries(format3);
  const value = format3[key];
  entries.splice(entries.findIndex(([name]) => name === key) + 1, 0, [key1, value], [key2, value]);
  return Object.fromEntries(entries);
}
function formatTitle(i, index2, { title }) {
  return this.format.title(title.value[i], i);
}
function* formatChannels(i, index2, channels, scales, values2) {
  for (const key in channels) {
    if (key === "fx" || key === "fy") {
      yield {
        label: formatLabel(scales, channels, key),
        value: this.format[key](index2[key], i)
      };
      continue;
    }
    if (key === "x1" && "x2" in channels) continue;
    if (key === "y1" && "y2" in channels) continue;
    const channel = channels[key];
    if (key === "x2" && "x1" in channels) {
      yield {
        label: formatPairLabel(scales, channels, "x"),
        value: formatPair(this.format.x2, channels.x1, channel, i)
      };
    } else if (key === "y2" && "y1" in channels) {
      yield {
        label: formatPairLabel(scales, channels, "y"),
        value: formatPair(this.format.y2, channels.y1, channel, i)
      };
    } else {
      const value = channel.value[i];
      const scale3 = channel.scale;
      if (!defined(value) && scale3 == null) continue;
      yield {
        label: formatLabel(scales, channels, key),
        value: this.format[key](value, i),
        color: scale3 === "color" ? values2[key][i] : null,
        opacity: scale3 === "opacity" ? values2[key][i] : null
      };
    }
  }
}
function formatPair(formatValue, c1, c22, i) {
  var _a;
  return ((_a = c22.hint) == null ? void 0 : _a.length) ? `${formatValue(c22.value[i] - c1.value[i], i)}` : `${formatValue(c1.value[i], i)}–${formatValue(c22.value[i], i)}`;
}
function formatPairLabel(scales, channels, key) {
  const l1 = formatLabel(scales, channels, `${key}1`, key);
  const l2 = formatLabel(scales, channels, `${key}2`, key);
  return l1 === l2 ? l1 : `${l1}–${l2}`;
}
function formatLabel(scales, channels, key, defaultLabel = key) {
  const channel = channels[key];
  const scale3 = scales[(channel == null ? void 0 : channel.scale) ?? key];
  return String((scale3 == null ? void 0 : scale3.label) ?? (channel == null ? void 0 : channel.label) ?? defaultLabel);
}

// node_modules/@observablehq/plot/src/plot.js
function plot(options = {}) {
  var _a;
  const { facet, style, title, subtitle, caption, ariaLabel, ariaDescription } = options;
  const className = maybeClassName(options.className);
  const marks2 = options.marks === void 0 ? [] : flatMarks(options.marks);
  marks2.push(...inferTips(marks2));
  const topFacetState = maybeTopFacet(facet, options);
  const facetStateByMark = /* @__PURE__ */ new Map();
  for (const mark of marks2) {
    const facetState = maybeMarkFacet(mark, topFacetState, options);
    if (facetState) facetStateByMark.set(mark, facetState);
  }
  const channelsByScale = /* @__PURE__ */ new Map();
  if (topFacetState) addScaleChannels(channelsByScale, [topFacetState], options);
  addScaleChannels(channelsByScale, facetStateByMark, options);
  const axes = flatMarks(inferAxes(marks2, channelsByScale, options));
  for (const mark of axes) {
    const facetState = maybeMarkFacet(mark, topFacetState, options);
    if (facetState) facetStateByMark.set(mark, facetState);
  }
  marks2.unshift(...axes);
  let facets = createFacets(channelsByScale, options);
  if (facets !== void 0) {
    const topFacetsIndex = topFacetState ? facetFilter(facets, topFacetState) : void 0;
    for (const mark of marks2) {
      if (mark.facet === null || mark.facet === "super") continue;
      const facetState = facetStateByMark.get(mark);
      if (facetState === void 0) continue;
      facetState.facetsIndex = mark.fx != null || mark.fy != null ? facetFilter(facets, facetState) : topFacetsIndex;
    }
    const nonEmpty = /* @__PURE__ */ new Set();
    for (const { facetsIndex } of facetStateByMark.values()) {
      facetsIndex == null ? void 0 : facetsIndex.forEach((index2, i) => {
        if ((index2 == null ? void 0 : index2.length) > 0) {
          nonEmpty.add(i);
        }
      });
    }
    facets.forEach(
      0 < nonEmpty.size && nonEmpty.size < facets.length ? (f, i) => f.empty = !nonEmpty.has(i) : (f) => f.empty = false
    );
    for (const mark of marks2) {
      if (mark.facet === "exclude") {
        const facetState = facetStateByMark.get(mark);
        if (facetState !== void 0) facetState.facetsIndex = facetExclude(facetState.facetsIndex);
      }
    }
  }
  for (const key of registry.keys()) {
    if (isScaleOptions(options[key]) && key !== "fx" && key !== "fy") {
      channelsByScale.set(key, []);
    }
  }
  const stateByMark = /* @__PURE__ */ new Map();
  for (const mark of marks2) {
    if (stateByMark.has(mark)) throw new Error("duplicate mark; each mark must be unique");
    const { facetsIndex, channels: facetChannels } = facetStateByMark.get(mark) ?? {};
    const { data, facets: facets2, channels } = mark.initialize(facetsIndex, facetChannels, options);
    applyScaleTransforms(channels, options);
    stateByMark.set(mark, { data, facets: facets2, channels });
  }
  const scaleDescriptors = createScales(addScaleChannels(channelsByScale, stateByMark, options), options);
  const dimensions = createDimensions(scaleDescriptors, marks2, options);
  autoScaleRange(scaleDescriptors, dimensions);
  const scales = createScaleFunctions(scaleDescriptors);
  const { fx, fy } = scales;
  const subdimensions = fx || fy ? innerDimensions(scaleDescriptors, dimensions) : dimensions;
  const superdimensions = fx || fy ? actualDimensions(scales, dimensions) : dimensions;
  const context = createContext(options);
  const document2 = context.document;
  const svg2 = creator_default("svg").call(document2.documentElement);
  let figure = svg2;
  context.ownerSVGElement = svg2;
  context.className = className;
  context.projection = createProjection(options, subdimensions);
  context.path = function() {
    return path_default(this.projection ?? xyProjection(scales));
  };
  context.filterFacets = (data, channels) => {
    return facetFilter(facets, { channels, groups: facetGroups(data, channels) });
  };
  context.getMarkState = (mark) => {
    const state = stateByMark.get(mark);
    const facetState = facetStateByMark.get(mark);
    return { ...state, channels: { ...state.channels, ...facetState == null ? void 0 : facetState.channels } };
  };
  context.dispatchValue = (value) => {
    if (figure.value === value) return;
    figure.value = value;
    figure.dispatchEvent(new context.document.defaultView.Event("input", { bubbles: true }));
  };
  const newByScale = /* @__PURE__ */ new Set();
  for (const [mark, state] of stateByMark) {
    if (mark.initializer != null) {
      const dimensions2 = mark.facet === "super" ? superdimensions : subdimensions;
      const update = mark.initializer(state.data, state.facets, state.channels, scales, dimensions2, context);
      if (update.data !== void 0) {
        state.data = update.data;
      }
      if (update.facets !== void 0) {
        state.facets = update.facets;
      }
      if (update.channels !== void 0) {
        const { fx: fx2, fy: fy2, ...channels } = update.channels;
        inferChannelScales(channels);
        Object.assign(state.channels, channels);
        for (const channel of Object.values(channels)) {
          const { scale: scale3 } = channel;
          if (scale3 != null && !isPosition(registry.get(scale3))) {
            applyScaleTransform(channel, options);
            newByScale.add(scale3);
          }
        }
        if (fx2 != null || fy2 != null) facetStateByMark.set(mark, true);
      }
    }
  }
  if (newByScale.size) {
    const newChannelsByScale = /* @__PURE__ */ new Map();
    addScaleChannels(newChannelsByScale, stateByMark, options, (key) => newByScale.has(key));
    addScaleChannels(channelsByScale, stateByMark, options, (key) => newByScale.has(key));
    const newScaleDescriptors = inheritScaleLabels(createScales(newChannelsByScale, options), scaleDescriptors);
    const { scales: newExposedScales, ...newScales } = createScaleFunctions(newScaleDescriptors);
    Object.assign(scaleDescriptors, newScaleDescriptors);
    Object.assign(scales, newScales);
    Object.assign(scales.scales, newExposedScales);
  }
  let facetDomains, facetTranslate;
  if (facets !== void 0) {
    facetDomains = { x: fx == null ? void 0 : fx.domain(), y: fy == null ? void 0 : fy.domain() };
    facets = recreateFacets(facets, facetDomains);
    facetTranslate = facetTranslator(fx, fy, dimensions);
  }
  for (const [mark, state] of stateByMark) {
    state.values = mark.scale(state.channels, scales, context);
  }
  const { width, height } = dimensions;
  select_default2(svg2).attr("class", className).attr("fill", "currentColor").attr("font-family", "system-ui, sans-serif").attr("font-size", 10).attr("text-anchor", "middle").attr("width", width).attr("height", height).attr("viewBox", `0 0 ${width} ${height}`).attr("aria-label", ariaLabel).attr("aria-description", ariaDescription).call(
    (svg3) => (
      // Warning: if you edit this, change defaultClassName.
      svg3.append("style").text(
        `:where(.${className}) {
  --plot-background: white;
  display: block;
  height: auto;
  height: intrinsic;
  max-width: 100%;
}
:where(.${className} text),
:where(.${className} tspan) {
  white-space: pre;
}`
      )
    )
  ).call(applyInlineStyles, style);
  for (const mark of marks2) {
    const { channels, values: values2, facets: indexes2 } = stateByMark.get(mark);
    if (facets === void 0 || mark.facet === "super") {
      let index2 = null;
      if (indexes2) {
        index2 = indexes2[0];
        index2 = mark.filter(index2, channels, values2);
        if (index2.length === 0) continue;
      }
      const node = mark.render(index2, scales, values2, superdimensions, context);
      if (node == null) continue;
      svg2.appendChild(node);
    } else {
      let g;
      for (const f of facets) {
        if (!(((_a = mark.facetAnchor) == null ? void 0 : _a.call(mark, facets, facetDomains, f)) ?? !f.empty)) continue;
        let index2 = null;
        if (indexes2) {
          const faceted = facetStateByMark.has(mark);
          index2 = indexes2[faceted ? f.i : 0];
          index2 = mark.filter(index2, channels, values2);
          if (index2.length === 0) continue;
          if (!faceted && index2 === indexes2[0]) index2 = subarray(index2);
          index2.fx = f.x, index2.fy = f.y, index2.fi = f.i;
        }
        const node = mark.render(index2, scales, values2, subdimensions, context);
        if (node == null) continue;
        (g ?? (g = select_default2(svg2).append("g"))).append(() => node).datum(f);
        for (const name of ["aria-label", "aria-description", "aria-hidden", "transform"]) {
          if (node.hasAttribute(name)) {
            g.attr(name, node.getAttribute(name));
            node.removeAttribute(name);
          }
        }
      }
      g == null ? void 0 : g.selectChildren().each(facetTranslate);
    }
  }
  const legends = createLegends(scaleDescriptors, context, options);
  const { figure: figured = title != null || subtitle != null || caption != null || legends.length > 0 } = options;
  if (figured) {
    figure = document2.createElement("figure");
    figure.className = `${className}-figure`;
    figure.style.maxWidth = "initial";
    if (title != null) figure.append(createTitleElement(document2, title, "h2"));
    if (subtitle != null) figure.append(createTitleElement(document2, subtitle, "h3"));
    figure.append(...legends, svg2);
    if (caption != null) figure.append(createFigcaption(document2, caption));
    if ("value" in svg2) figure.value = svg2.value, delete svg2.value;
  }
  figure.scale = exposeScales(scales.scales);
  figure.legend = exposeLegends(scaleDescriptors, context, options);
  const w = consumeWarnings();
  if (w > 0) {
    select_default2(svg2).append("text").attr("x", width).attr("y", 20).attr("dy", "-1em").attr("text-anchor", "end").attr("font-family", "initial").text("⚠️").append("title").text(`${w.toLocaleString("en-US")} warning${w === 1 ? "" : "s"}. Please check the console.`);
  }
  return figure;
}
function createTitleElement(document2, contents, tag) {
  if (contents.ownerDocument) return contents;
  const e = document2.createElement(tag);
  e.append(contents);
  return e;
}
function createFigcaption(document2, caption) {
  const e = document2.createElement("figcaption");
  e.append(caption);
  return e;
}
function flatMarks(marks2) {
  return marks2.flat(Infinity).filter((mark) => mark != null).map(markify);
}
function markify(mark) {
  return typeof mark.render === "function" ? mark : new Render(mark);
}
var Render = class extends Mark {
  constructor(render) {
    if (typeof render !== "function") throw new TypeError("invalid mark; missing render function");
    super();
    this.render = render;
  }
  render() {
  }
};
function applyScaleTransforms(channels, options) {
  for (const name in channels) applyScaleTransform(channels[name], options);
  return channels;
}
function applyScaleTransform(channel, options) {
  const { scale: scale3, transform: t = true } = channel;
  if (scale3 == null || !t) return;
  const {
    type: type2,
    percent,
    interval: interval2,
    transform: transform2 = percent ? (x3) => x3 == null ? NaN : x3 * 100 : maybeIntervalTransform(interval2, type2)
  } = options[scale3] ?? {};
  if (transform2 == null) return;
  channel.value = map4(channel.value, transform2);
  channel.transform = false;
}
function inferChannelScales(channels) {
  for (const name in channels) {
    inferChannelScale(name, channels[name]);
  }
}
function addScaleChannels(channelsByScale, stateByMark, options, filter4 = yes) {
  var _a, _b;
  for (const { channels } of stateByMark.values()) {
    for (const name in channels) {
      const channel = channels[name];
      const { scale: scale3 } = channel;
      if (scale3 != null && filter4(scale3)) {
        if (scale3 === "projection") {
          if (!hasProjection(options)) {
            const gx = ((_a = options.x) == null ? void 0 : _a.domain) === void 0;
            const gy = ((_b = options.y) == null ? void 0 : _b.domain) === void 0;
            if (gx || gy) {
              const [x3, y3] = getGeometryChannels(channel);
              if (gx) addScaleChannel(channelsByScale, "x", x3);
              if (gy) addScaleChannel(channelsByScale, "y", y3);
            }
          }
        } else {
          addScaleChannel(channelsByScale, scale3, channel);
        }
      }
    }
  }
  return channelsByScale;
}
function addScaleChannel(channelsByScale, scale3, channel) {
  const scaleChannels = channelsByScale.get(scale3);
  if (scaleChannels !== void 0) scaleChannels.push(channel);
  else channelsByScale.set(scale3, [channel]);
}
function maybeTopFacet(facet, options) {
  if (facet == null) return;
  const { x: x3, y: y3 } = facet;
  if (x3 == null && y3 == null) return;
  const data = dataify(facet.data);
  if (data == null) throw new Error("missing facet data");
  const channels = {};
  if (x3 != null) channels.fx = createChannel(data, { value: x3, scale: "fx" });
  if (y3 != null) channels.fy = createChannel(data, { value: y3, scale: "fy" });
  applyScaleTransforms(channels, options);
  const groups2 = facetGroups(data, channels);
  return { channels, groups: groups2, data: facet.data };
}
function maybeMarkFacet(mark, topFacetState, options) {
  if (mark.facet === null || mark.facet === "super") return;
  const { fx, fy } = mark;
  if (fx != null || fy != null) {
    const data2 = dataify(mark.data ?? fx ?? fy);
    if (data2 === void 0) throw new Error(`missing facet data in ${mark.ariaLabel}`);
    if (data2 === null) return;
    const channels2 = {};
    if (fx != null) channels2.fx = createChannel(data2, { value: fx, scale: "fx" });
    if (fy != null) channels2.fy = createChannel(data2, { value: fy, scale: "fy" });
    applyScaleTransforms(channels2, options);
    return { channels: channels2, groups: facetGroups(data2, channels2) };
  }
  if (topFacetState === void 0) return;
  const { channels, groups: groups2, data } = topFacetState;
  if (mark.facet !== "auto" || mark.data === data) return { channels, groups: groups2 };
  if (data.length > 0 && (groups2.size > 1 || groups2.size === 1 && channels.fx && channels.fy && [...groups2][0][1].size > 1) && lengthof(dataify(mark.data)) === lengthof(data)) {
    warn(
      `Warning: the ${mark.ariaLabel} mark appears to use faceted data, but isn’t faceted. The mark data has the same length as the facet data and the mark facet option is "auto", but the mark data and facet data are distinct. If this mark should be faceted, set the mark facet option to true; otherwise, suppress this warning by setting the mark facet option to false.`
    );
  }
}
function derive(mark, options = {}) {
  return initializer({ ...options, x: null, y: null }, (data, facets, channels, scales, dimensions, context) => {
    return context.getMarkState(mark);
  });
}
function inferTips(marks2) {
  const tips = [];
  for (const mark of marks2) {
    let tipOptions = mark.tip;
    if (tipOptions) {
      if (tipOptions === true) tipOptions = {};
      else if (typeof tipOptions === "string") tipOptions = { pointer: tipOptions };
      let { pointer: p, preferredAnchor: a2 } = tipOptions;
      p = /^x$/i.test(p) ? pointerX : /^y$/i.test(p) ? pointerY : pointer;
      tipOptions = p(derive(mark, tipOptions));
      tipOptions.title = null;
      if (a2 === void 0) tipOptions.preferredAnchor = p === pointerY ? "left" : "bottom";
      const t = tip(mark.data, tipOptions);
      t.facet = mark.facet;
      t.facetAnchor = mark.facetAnchor;
      tips.push(t);
    }
  }
  return tips;
}
function inferAxes(marks2, channelsByScale, options) {
  let {
    projection: projection3,
    x: x3 = {},
    y: y3 = {},
    fx = {},
    fy = {},
    axis: axis2,
    grid,
    facet = {},
    facet: { axis: facetAxis = axis2, grid: facetGrid } = facet,
    x: { axis: xAxis = axis2, grid: xGrid = xAxis === null ? null : grid } = x3,
    y: { axis: yAxis = axis2, grid: yGrid = yAxis === null ? null : grid } = y3,
    fx: { axis: fxAxis = facetAxis, grid: fxGrid = fxAxis === null ? null : facetGrid } = fx,
    fy: { axis: fyAxis = facetAxis, grid: fyGrid = fyAxis === null ? null : facetGrid } = fy
  } = options;
  if (projection3 || !isScaleOptions(x3) && !hasPositionChannel("x", marks2)) xAxis = xGrid = null;
  if (projection3 || !isScaleOptions(y3) && !hasPositionChannel("y", marks2)) yAxis = yGrid = null;
  if (!channelsByScale.has("fx")) fxAxis = fxGrid = null;
  if (!channelsByScale.has("fy")) fyAxis = fyGrid = null;
  if (xAxis === void 0) xAxis = !hasAxis(marks2, "x");
  if (yAxis === void 0) yAxis = !hasAxis(marks2, "y");
  if (fxAxis === void 0) fxAxis = !hasAxis(marks2, "fx");
  if (fyAxis === void 0) fyAxis = !hasAxis(marks2, "fy");
  if (xAxis === true) xAxis = "bottom";
  if (yAxis === true) yAxis = "left";
  if (fxAxis === true) fxAxis = xAxis === "top" || xAxis === null ? "bottom" : "top";
  if (fyAxis === true) fyAxis = yAxis === "right" || yAxis === null ? "left" : "right";
  const axes = [];
  maybeGrid(axes, fyGrid, gridFy, fy);
  maybeAxis(axes, fyAxis, axisFy, "right", "left", facet, fy);
  maybeGrid(axes, fxGrid, gridFx, fx);
  maybeAxis(axes, fxAxis, axisFx, "top", "bottom", facet, fx);
  maybeGrid(axes, yGrid, gridY, y3);
  maybeAxis(axes, yAxis, axisY, "left", "right", options, y3);
  maybeGrid(axes, xGrid, gridX, x3);
  maybeAxis(axes, xAxis, axisX, "bottom", "top", options, x3);
  return axes;
}
function maybeAxis(axes, axis2, axisType, primary, secondary, defaults22, options) {
  if (!axis2) return;
  const both = isBoth(axis2);
  options = axisOptions(both ? primary : axis2, defaults22, options);
  const { line: line2 } = options;
  if ((axisType === axisY || axisType === axisX) && line2 && !isNone(line2)) axes.push(frame2(lineOptions(options)));
  axes.push(axisType(options));
  if (both) axes.push(axisType({ ...options, anchor: secondary, label: null }));
}
function maybeGrid(axes, grid, gridType, options) {
  if (!grid || isNone(grid)) return;
  axes.push(gridType(gridOptions(grid, options)));
}
function isBoth(value) {
  return /^\s*both\s*$/i.test(value);
}
function axisOptions(anchor, defaults22, {
  line: line2 = defaults22.line,
  ticks: ticks2,
  tickSize,
  tickSpacing,
  tickPadding,
  tickFormat: tickFormat2,
  tickRotate,
  fontVariant,
  ariaLabel,
  ariaDescription,
  label = defaults22.label,
  labelAnchor,
  labelArrow = defaults22.labelArrow,
  labelOffset
}) {
  return {
    anchor,
    line: line2,
    ticks: ticks2,
    tickSize,
    tickSpacing,
    tickPadding,
    tickFormat: tickFormat2,
    tickRotate,
    fontVariant,
    ariaLabel,
    ariaDescription,
    label,
    labelAnchor,
    labelArrow,
    labelOffset
  };
}
function lineOptions(options) {
  const { anchor, line: line2 } = options;
  return { anchor, facetAnchor: anchor + "-empty", stroke: line2 === true ? void 0 : line2 };
}
function gridOptions(grid, {
  stroke = isColor(grid) ? grid : void 0,
  ticks: ticks2 = isGridTicks(grid) ? grid : void 0,
  tickSpacing,
  ariaLabel,
  ariaDescription
}) {
  return {
    stroke,
    ticks: ticks2,
    tickSpacing,
    ariaLabel,
    ariaDescription
  };
}
function isGridTicks(grid) {
  switch (typeof grid) {
    case "number":
      return true;
    case "string":
      return !isColor(grid);
  }
  return isIterable(grid) || typeof (grid == null ? void 0 : grid.range) === "function";
}
function hasAxis(marks2, k2) {
  const prefix = `${k2}-axis `;
  return marks2.some((m) => {
    var _a;
    return (_a = m.ariaLabel) == null ? void 0 : _a.startsWith(prefix);
  });
}
function hasPositionChannel(k2, marks2) {
  for (const mark of marks2) {
    for (const key in mark.channels) {
      const { scale: scale3 } = mark.channels[key];
      if (scale3 === k2 || scale3 === "projection") {
        return true;
      }
    }
  }
  return false;
}
function inheritScaleLabels(newScales, scales) {
  for (const key in newScales) {
    const newScale = newScales[key];
    const scale3 = scales[key];
    if (newScale.label === void 0 && scale3) {
      newScale.label = scale3.label;
    }
  }
  return newScales;
}
function actualDimensions({ fx, fy }, dimensions) {
  const { marginTop, marginRight, marginBottom, marginLeft, width, height } = outerDimensions(dimensions);
  const fxr = fx && outerRange(fx);
  const fyr = fy && outerRange(fy);
  return {
    marginTop: fy ? fyr[0] : marginTop,
    marginRight: fx ? width - fxr[1] : marginRight,
    marginBottom: fy ? height - fyr[1] : marginBottom,
    marginLeft: fx ? fxr[0] : marginLeft,
    // Some marks, namely the x- and y-axis labels, want to know what the
    // desired (rather than actual) margins are for positioning.
    inset: {
      marginTop: dimensions.marginTop,
      marginRight: dimensions.marginRight,
      marginBottom: dimensions.marginBottom,
      marginLeft: dimensions.marginLeft
    },
    width,
    height
  };
}
function outerRange(scale3) {
  const domain = scale3.domain();
  if (domain.length === 0) return [0, scale3.bandwidth()];
  let x12 = scale3(domain[0]);
  let x22 = scale3(domain[domain.length - 1]);
  if (x22 < x12) [x12, x22] = [x22, x12];
  return [x12, x22 + scale3.bandwidth()];
}

// node_modules/@observablehq/plot/src/curve.js
var curves = /* @__PURE__ */ new Map([
  ["basis", basis_default2],
  ["basis-closed", basisClosed_default2],
  ["basis-open", basisOpen_default],
  ["bundle", bundle_default],
  ["bump-x", bumpX],
  ["bump-y", bumpY],
  ["cardinal", cardinal_default],
  ["cardinal-closed", cardinalClosed_default],
  ["cardinal-open", cardinalOpen_default],
  ["catmull-rom", catmullRom_default],
  ["catmull-rom-closed", catmullRomClosed_default],
  ["catmull-rom-open", catmullRomOpen_default],
  ["linear", linear_default],
  ["linear-closed", linearClosed_default],
  ["monotone-x", monotoneX],
  ["monotone-y", monotoneY],
  ["natural", natural_default],
  ["step", step_default],
  ["step-after", stepAfter],
  ["step-before", stepBefore]
]);
function maybeCurve(curve = linear_default, tension) {
  if (typeof curve === "function") return curve;
  const c4 = curves.get(`${curve}`.toLowerCase());
  if (!c4) throw new Error(`unknown curve: ${curve}`);
  if (tension !== void 0) {
    if ("beta" in c4) {
      return c4.beta(tension);
    } else if ("tension" in c4) {
      return c4.tension(tension);
    } else if ("alpha" in c4) {
      return c4.alpha(tension);
    }
  }
  return c4;
}
function maybeCurveAuto(curve = curveAuto, tension) {
  return typeof curve !== "function" && `${curve}`.toLowerCase() === "auto" ? curveAuto : maybeCurve(curve, tension);
}
function curveAuto(context) {
  return linear_default(context);
}

// node_modules/@observablehq/plot/src/transforms/bin.js
function binX(outputs = { y: "count" }, options = {}) {
  [outputs, options] = mergeOptions2(outputs, options);
  const { x: x3, y: y3 } = options;
  return binn(maybeBinValue(x3, options, identity6), null, null, y3, outputs, maybeInsetX(options));
}
function binY(outputs = { x: "count" }, options = {}) {
  [outputs, options] = mergeOptions2(outputs, options);
  const { x: x3, y: y3 } = options;
  return binn(null, maybeBinValue(y3, options, identity6), x3, null, outputs, maybeInsetY(options));
}
function bin2(outputs = { fill: "count" }, options = {}) {
  [outputs, options] = mergeOptions2(outputs, options);
  const { x: x3, y: y3 } = maybeBinValueTuple(options);
  return binn(x3, y3, null, null, outputs, maybeInsetX(maybeInsetY(options)));
}
function maybeDenseInterval(bin3, k2, options = {}) {
  if ((options == null ? void 0 : options.interval) == null) return options;
  const { reduce: reduce2 = reduceFirst } = options;
  const outputs = { filter: null };
  if (options[k2] != null) outputs[k2] = reduce2;
  if (options[`${k2}1`] != null) outputs[`${k2}1`] = reduce2;
  if (options[`${k2}2`] != null) outputs[`${k2}2`] = reduce2;
  return bin3(outputs, options);
}
function maybeDenseIntervalX(options = {}) {
  return maybeDenseInterval(binX, "y", withTip(options, "x"));
}
function maybeDenseIntervalY(options = {}) {
  return maybeDenseInterval(binY, "x", withTip(options, "y"));
}
function binn(bx, by, gx, gy, {
  data: reduceData = reduceIdentity,
  // TODO avoid materializing when unused?
  filter: filter4 = reduceCount,
  // return only non-empty bins by default
  sort: sort3,
  reverse: reverse3,
  ...outputs
  // output channel definitions
} = {}, inputs = {}) {
  bx = maybeBin(bx);
  by = maybeBin(by);
  outputs = maybeBinOutputs(outputs, inputs);
  reduceData = maybeBinReduce(reduceData, identity6);
  sort3 = sort3 == null ? void 0 : maybeBinOutput("sort", sort3, inputs);
  filter4 = filter4 == null ? void 0 : maybeBinEvaluator("filter", filter4, inputs);
  if (gx != null && hasOutput(outputs, "x", "x1", "x2")) gx = null;
  if (gy != null && hasOutput(outputs, "y", "y1", "y2")) gy = null;
  const [BX1, setBX1] = maybeColumn(bx);
  const [BX2, setBX2] = maybeColumn(bx);
  const [BY1, setBY1] = maybeColumn(by);
  const [BY2, setBY2] = maybeColumn(by);
  const [k2, gk] = gx != null ? [gx, "x"] : gy != null ? [gy, "y"] : [];
  const [GK, setGK] = maybeColumn(k2);
  const {
    x: x3,
    y: y3,
    z,
    fill,
    stroke,
    x1: x12,
    x2: x22,
    // consumed if x is an output
    y1: y12,
    y2: y22,
    // consumed if y is an output
    domain,
    cumulative,
    thresholds,
    interval: interval2,
    ...options
  } = inputs;
  const [GZ, setGZ] = maybeColumn(z);
  const [vfill] = maybeColorChannel(fill);
  const [vstroke] = maybeColorChannel(stroke);
  const [GF, setGF] = maybeColumn(vfill);
  const [GS, setGS] = maybeColumn(vstroke);
  return {
    ..."z" in inputs && { z: GZ || z },
    ..."fill" in inputs && { fill: GF || fill },
    ..."stroke" in inputs && { stroke: GS || stroke },
    ...basic(options, (data, facets, plotOptions) => {
      const K2 = maybeApplyInterval(valueof(data, k2), plotOptions == null ? void 0 : plotOptions[gk]);
      const Z = valueof(data, z);
      const F = valueof(data, vfill);
      const S = valueof(data, vstroke);
      const G = maybeSubgroup(outputs, { z: Z, fill: F, stroke: S });
      const groupFacets = [];
      const groupData = [];
      const GK2 = K2 && setGK([]);
      const GZ2 = Z && setGZ([]);
      const GF2 = F && setGF([]);
      const GS2 = S && setGS([]);
      const BX12 = bx && setBX1([]);
      const BX22 = bx && setBX2([]);
      const BY12 = by && setBY1([]);
      const BY22 = by && setBY2([]);
      const bin3 = bing(bx, by, data);
      let i = 0;
      for (const o of outputs) o.initialize(data);
      if (sort3) sort3.initialize(data);
      if (filter4) filter4.initialize(data);
      for (const facet of facets) {
        const groupFacet = [];
        for (const o of outputs) o.scope("facet", facet);
        if (sort3) sort3.scope("facet", facet);
        if (filter4) filter4.scope("facet", facet);
        for (const [f, I] of maybeGroup(facet, G)) {
          for (const [k3, g] of maybeGroup(I, K2)) {
            for (const [b, extent3] of bin3(g)) {
              if (G) extent3.z = f;
              if (filter4 && !filter4.reduce(b, extent3)) continue;
              groupFacet.push(i++);
              groupData.push(reduceData.reduceIndex(b, data, extent3));
              if (K2) GK2.push(k3);
              if (Z) GZ2.push(G === Z ? f : Z[(b.length > 0 ? b : g)[0]]);
              if (F) GF2.push(G === F ? f : F[(b.length > 0 ? b : g)[0]]);
              if (S) GS2.push(G === S ? f : S[(b.length > 0 ? b : g)[0]]);
              if (BX12) BX12.push(extent3.x1), BX22.push(extent3.x2);
              if (BY12) BY12.push(extent3.y1), BY22.push(extent3.y2);
              for (const o of outputs) o.reduce(b, extent3);
              if (sort3) sort3.reduce(b, extent3);
            }
          }
        }
        groupFacets.push(groupFacet);
      }
      maybeSort(groupFacets, sort3, reverse3);
      return { data: groupData, facets: groupFacets };
    }),
    ...!hasOutput(outputs, "x") && (BX1 ? { x1: BX1, x2: BX2, x: mid(BX1, BX2) } : { x: x3, x1: x12, x2: x22 }),
    ...!hasOutput(outputs, "y") && (BY1 ? { y1: BY1, y2: BY2, y: mid(BY1, BY2) } : { y: y3, y1: y12, y2: y22 }),
    ...GK && { [gk]: GK },
    ...Object.fromEntries(outputs.map(({ name, output }) => [name, output]))
  };
}
function mergeOptions2({ cumulative, domain, thresholds, interval: interval2, ...outputs }, options) {
  return [outputs, { cumulative, domain, thresholds, interval: interval2, ...options }];
}
function maybeBinValue(value, { cumulative, domain, thresholds, interval: interval2 }, defaultValue) {
  value = { ...maybeValue(value) };
  if (value.domain === void 0) value.domain = domain;
  if (value.cumulative === void 0) value.cumulative = cumulative;
  if (value.thresholds === void 0) value.thresholds = thresholds;
  if (value.interval === void 0) value.interval = interval2;
  if (value.value === void 0) value.value = defaultValue;
  value.thresholds = maybeThresholds(value.thresholds, value.interval);
  return value;
}
function maybeBinValueTuple(options) {
  let { x: x3, y: y3 } = options;
  x3 = maybeBinValue(x3, options);
  y3 = maybeBinValue(y3, options);
  [x3.value, y3.value] = maybeTuple(x3.value, y3.value);
  return { x: x3, y: y3 };
}
function maybeBin(options) {
  if (options == null) return;
  const { value, cumulative, domain = extent, thresholds } = options;
  const bin3 = (data) => {
    let V = valueof(data, value);
    let T;
    if (isTemporal(V) || isTimeThresholds(thresholds)) {
      V = map4(V, coerceDate, Float64Array);
      let [min4, max5] = typeof domain === "function" ? domain(V) : domain;
      let t = typeof thresholds === "function" && !isInterval(thresholds) ? thresholds(V, min4, max5) : thresholds;
      if (typeof t === "number") t = utcTickInterval(min4, max5, t);
      if (isInterval(t)) {
        if (domain === extent) {
          min4 = t.floor(min4);
          max5 = t.offset(t.floor(max5));
        }
        t = t.range(min4, t.offset(max5));
      }
      T = t;
    } else {
      V = coerceNumbers(V);
      let [min4, max5] = typeof domain === "function" ? domain(V) : domain;
      let t = typeof thresholds === "function" && !isInterval(thresholds) ? thresholds(V, min4, max5) : thresholds;
      if (typeof t === "number") {
        if (domain === extent) {
          let step = tickIncrement(min4, max5, t);
          if (isFinite(step)) {
            if (step > 0) {
              let r0 = Math.round(min4 / step);
              let r1 = Math.round(max5 / step);
              if (!(r0 * step <= min4)) --r0;
              if (!(r1 * step > max5)) ++r1;
              let n = r1 - r0 + 1;
              t = new Float64Array(n);
              for (let i = 0; i < n; ++i) t[i] = (r0 + i) * step;
            } else if (step < 0) {
              step = -step;
              let r0 = Math.round(min4 * step);
              let r1 = Math.round(max5 * step);
              if (!(r0 / step <= min4)) --r0;
              if (!(r1 / step > max5)) ++r1;
              let n = r1 - r0 + 1;
              t = new Float64Array(n);
              for (let i = 0; i < n; ++i) t[i] = (r0 + i) / step;
            } else {
              t = [min4];
            }
          } else {
            t = [min4];
          }
        } else {
          t = ticks(min4, max5, t);
        }
      } else if (isInterval(t)) {
        if (domain === extent) {
          min4 = t.floor(min4);
          max5 = t.offset(t.floor(max5));
        }
        t = t.range(min4, t.offset(max5));
      }
      T = t;
    }
    const E2 = [];
    if (T.length === 1) E2.push([T[0], T[0]]);
    else for (let i = 1; i < T.length; ++i) E2.push([T[i - 1], T[i]]);
    E2.bin = (cumulative < 0 ? bin1cn : cumulative > 0 ? bin1cp : bin1)(E2, T, V);
    return E2;
  };
  bin3.label = labelof(value);
  return bin3;
}
function maybeThresholds(thresholds, interval2, defaultThresholds = thresholdAuto) {
  if (thresholds === void 0) {
    return interval2 === void 0 ? defaultThresholds : maybeRangeInterval(interval2);
  }
  if (typeof thresholds === "string") {
    switch (thresholds.toLowerCase()) {
      case "freedman-diaconis":
        return thresholdFreedmanDiaconis;
      case "scott":
        return thresholdScott;
      case "sturges":
        return thresholdSturges;
      case "auto":
        return thresholdAuto;
    }
    return utcInterval(thresholds);
  }
  return thresholds;
}
function maybeBinOutputs(outputs, inputs) {
  return maybeOutputs(outputs, inputs, maybeBinOutput);
}
function maybeBinOutput(name, reduce2, inputs) {
  return maybeOutput(name, reduce2, inputs, maybeBinEvaluator);
}
function maybeBinEvaluator(name, reduce2, inputs) {
  return maybeEvaluator(name, reduce2, inputs, maybeBinReduce);
}
function maybeBinReduce(reduce2, value) {
  return maybeReduce(reduce2, value, maybeBinReduceFallback);
}
function maybeBinReduceFallback(reduce2) {
  switch (`${reduce2}`.toLowerCase()) {
    case "x":
      return reduceX2;
    case "x1":
      return reduceX1;
    case "x2":
      return reduceX22;
    case "y":
      return reduceY2;
    case "y1":
      return reduceY1;
    case "y2":
      return reduceY22;
    case "z":
      return reduceZ;
  }
  throw new Error(`invalid bin reduce: ${reduce2}`);
}
function thresholdAuto(values2, min4, max5) {
  return Math.min(200, thresholdScott(values2, min4, max5));
}
function isTimeThresholds(t) {
  return isTimeInterval(t) || isIterable(t) && isTemporal(t);
}
function bing(bx, by, data) {
  const EX = bx == null ? void 0 : bx(data);
  const EY = by == null ? void 0 : by(data);
  return EX && EY ? function* (I) {
    const X3 = EX.bin(I);
    for (const [ix, [x12, x22]] of EX.entries()) {
      const Y3 = EY.bin(X3[ix]);
      for (const [iy, [y12, y22]] of EY.entries()) {
        yield [Y3[iy], { data, x1: x12, y1: y12, x2: x22, y2: y22 }];
      }
    }
  } : EX ? function* (I) {
    const X3 = EX.bin(I);
    for (const [i, [x12, x22]] of EX.entries()) {
      yield [X3[i], { data, x1: x12, x2: x22 }];
    }
  } : function* (I) {
    const Y3 = EY.bin(I);
    for (const [i, [y12, y22]] of EY.entries()) {
      yield [Y3[i], { data, y1: y12, y2: y22 }];
    }
  };
}
function bin1(E2, T, V) {
  T = coerceNumbers(T);
  return (I) => {
    var _a;
    const B3 = E2.map(() => []);
    for (const i of I) (_a = B3[bisect_default(T, V[i]) - 1]) == null ? void 0 : _a.push(i);
    return B3;
  };
}
function bin1cp(E2, T, V) {
  const bin3 = bin1(E2, T, V);
  return (I) => {
    const B3 = bin3(I);
    for (let i = 1, n = B3.length; i < n; ++i) {
      const C3 = B3[i - 1];
      const b = B3[i];
      for (const j of C3) b.push(j);
    }
    return B3;
  };
}
function bin1cn(E2, T, V) {
  const bin3 = bin1(E2, T, V);
  return (I) => {
    const B3 = bin3(I);
    for (let i = B3.length - 2; i >= 0; --i) {
      const C3 = B3[i + 1];
      const b = B3[i];
      for (const j of C3) b.push(j);
    }
    return B3;
  };
}
function mid1(x12, x22) {
  const m = (+x12 + +x22) / 2;
  return x12 instanceof Date ? new Date(m) : m;
}
var reduceX2 = {
  reduceIndex(I, X3, { x1: x12, x2: x22 }) {
    return mid1(x12, x22);
  }
};
var reduceY2 = {
  reduceIndex(I, X3, { y1: y12, y2: y22 }) {
    return mid1(y12, y22);
  }
};
var reduceX1 = {
  reduceIndex(I, X3, { x1: x12 }) {
    return x12;
  }
};
var reduceX22 = {
  reduceIndex(I, X3, { x2: x22 }) {
    return x22;
  }
};
var reduceY1 = {
  reduceIndex(I, X3, { y1: y12 }) {
    return y12;
  }
};
var reduceY22 = {
  reduceIndex(I, X3, { y2: y22 }) {
    return y22;
  }
};

// node_modules/@observablehq/plot/src/marks/area.js
var defaults7 = {
  ariaLabel: "area",
  strokeWidth: 1,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  strokeMiterlimit: 1
};
var Area = class extends Mark {
  constructor(data, options = {}) {
    const { x1: x12, y1: y12, x2: x22, y2: y22, z, curve, tension } = options;
    super(
      data,
      {
        x1: { value: x12, scale: "x" },
        y1: { value: y12, scale: "y" },
        x2: { value: x22, scale: "x", optional: true },
        y2: { value: y22, scale: "y", optional: true },
        z: { value: maybeZ(options), optional: true }
      },
      options,
      defaults7
    );
    this.z = z;
    this.curve = maybeCurve(curve, tension);
  }
  filter(index2) {
    return index2;
  }
  render(index2, scales, channels, dimensions, context) {
    const { x1: X13, y1: Y13, x2: X23 = X13, y2: Y23 = Y13 } = channels;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales, 0, 0).call(
      (g) => g.selectAll().data(groupIndex(index2, [X13, Y13, X23, Y23], this, channels)).enter().append("path").call(applyDirectStyles, this).call(applyGroupedChannelStyles, this, channels).attr(
        "d",
        area_default5().curve(this.curve).defined((i) => i >= 0).x0((i) => X13[i]).y0((i) => Y13[i]).x1((i) => X23[i]).y1((i) => Y23[i])
      )
    ).node();
  }
};
function area(data, options) {
  if (options === void 0) return areaY(data, { x: first, y: second2 });
  return new Area(data, options);
}
function areaX(data, options) {
  const { y: y3 = indexOf, ...rest } = maybeDenseIntervalY(options);
  return new Area(data, maybeStackX(maybeIdentityX({ ...rest, y1: y3, y2: void 0 }, y3 === indexOf ? "x2" : "x")));
}
function areaY(data, options) {
  const { x: x3 = indexOf, ...rest } = maybeDenseIntervalX(options);
  return new Area(data, maybeStackY(maybeIdentityY({ ...rest, x1: x3, x2: void 0 }, x3 === indexOf ? "y2" : "y")));
}

// node_modules/@observablehq/plot/src/marks/link.js
var defaults8 = {
  ariaLabel: "link",
  fill: "none",
  stroke: "currentColor",
  strokeMiterlimit: 1
};
var Link = class extends Mark {
  constructor(data, options = {}) {
    const { x1: x12, y1: y12, x2: x22, y2: y22, curve, tension } = options;
    super(
      data,
      {
        x1: { value: x12, scale: "x" },
        y1: { value: y12, scale: "y" },
        x2: { value: x22, scale: "x", optional: true },
        y2: { value: y22, scale: "y", optional: true }
      },
      options,
      defaults8
    );
    this.curve = maybeCurveAuto(curve, tension);
    markers(this, options);
  }
  project(channels, values2, context) {
    if (this.curve !== curveAuto) {
      super.project(channels, values2, context);
    }
  }
  render(index2, scales, channels, dimensions, context) {
    const { x1: X13, y1: Y13, x2: X23 = X13, y2: Y23 = Y13 } = channels;
    const { curve } = this;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call(
      (g) => g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).attr(
        "d",
        curve === curveAuto && context.projection ? sphereLink(context.path(), X13, Y13, X23, Y23) : (i) => {
          const p = pathRound();
          const c4 = curve(p);
          c4.lineStart();
          c4.point(X13[i], Y13[i]);
          c4.point(X23[i], Y23[i]);
          c4.lineEnd();
          return p;
        }
      ).call(applyChannelStyles, this, channels).call(applyMarkers, this, channels, context)
    ).node();
  }
};
function sphereLink(path2, X13, Y13, X23, Y23) {
  X13 = coerceNumbers(X13);
  Y13 = coerceNumbers(Y13);
  X23 = coerceNumbers(X23);
  Y23 = coerceNumbers(Y23);
  return (i) => path2({
    type: "LineString",
    coordinates: [
      [X13[i], Y13[i]],
      [X23[i], Y23[i]]
    ]
  });
}
function link3(data, { x: x3, x1: x12, x2: x22, y: y3, y1: y12, y2: y22, ...options } = {}) {
  [x12, x22] = maybeSameValue(x3, x12, x22);
  [y12, y22] = maybeSameValue(y3, y12, y22);
  return new Link(data, { ...options, x1: x12, x2: x22, y1: y12, y2: y22 });
}
function maybeSameValue(x3, x12, x22) {
  if (x3 === void 0) {
    if (x12 === void 0) {
      if (x22 !== void 0) return [x22];
    } else {
      if (x22 === void 0) return [x12];
    }
  } else if (x12 === void 0) {
    return x22 === void 0 ? [x3] : [x3, x22];
  } else if (x22 === void 0) {
    return [x3, x12];
  }
  return [x12, x22];
}

// node_modules/@observablehq/plot/src/marks/arrow.js
var defaults9 = {
  ariaLabel: "arrow",
  fill: "none",
  stroke: "currentColor",
  strokeLinecap: "round",
  strokeMiterlimit: 1,
  strokeWidth: 1.5
};
var Arrow = class extends Mark {
  constructor(data, options = {}) {
    const {
      x1: x12,
      y1: y12,
      x2: x22,
      y2: y22,
      bend = 0,
      headAngle = 60,
      headLength = 8,
      // Disable the arrow with headLength = 0; or, use Plot.link.
      inset = 0,
      insetStart = inset,
      insetEnd = inset,
      sweep
    } = options;
    super(
      data,
      {
        x1: { value: x12, scale: "x" },
        y1: { value: y12, scale: "y" },
        x2: { value: x22, scale: "x", optional: true },
        y2: { value: y22, scale: "y", optional: true }
      },
      options,
      defaults9
    );
    this.bend = bend === true ? 22.5 : Math.max(-90, Math.min(90, bend));
    this.headAngle = +headAngle;
    this.headLength = +headLength;
    this.insetStart = +insetStart;
    this.insetEnd = +insetEnd;
    this.sweep = maybeSweep(sweep);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x1: X13, y1: Y13, x2: X23 = X13, y2: Y23 = Y13, SW } = channels;
    const { strokeWidth, bend, headAngle, headLength, insetStart, insetEnd } = this;
    const sw = SW ? (i) => SW[i] : constant2(strokeWidth === void 0 ? 1 : strokeWidth);
    const wingAngle = headAngle * radians3 / 2;
    const wingScale = headLength / 1.5;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call(
      (g) => g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).attr("d", (i) => {
        let x12 = X13[i], y12 = Y13[i], x22 = X23[i], y22 = Y23[i];
        const lineLength = Math.hypot(x22 - x12, y22 - y12);
        if (lineLength <= insetStart + insetEnd) return null;
        let lineAngle = Math.atan2(y22 - y12, x22 - x12);
        const headLength2 = Math.min(wingScale * sw(i), lineLength / 3);
        const bendAngle = this.sweep(x12, y12, x22, y22) * bend * radians3;
        const r = Math.hypot(lineLength / Math.tan(bendAngle), lineLength) / 2;
        if (insetStart || insetEnd) {
          if (r < 1e5) {
            const sign3 = Math.sign(bendAngle);
            const [cx, cy] = pointPointCenter([x12, y12], [x22, y22], r, sign3);
            if (insetStart) {
              [x12, y12] = circleCircleIntersect([cx, cy, r], [x12, y12, insetStart], -sign3 * Math.sign(insetStart));
            }
            if (insetEnd) {
              const [x5, y5] = circleCircleIntersect([cx, cy, r], [x22, y22, insetEnd], sign3 * Math.sign(insetEnd));
              lineAngle += Math.atan2(y5 - cy, x5 - cx) - Math.atan2(y22 - cy, x22 - cx);
              x22 = x5, y22 = y5;
            }
          } else {
            const dx = x22 - x12, dy = y22 - y12, d = Math.hypot(dx, dy);
            if (insetStart) x12 += dx / d * insetStart, y12 += dy / d * insetStart;
            if (insetEnd) x22 -= dx / d * insetEnd, y22 -= dy / d * insetEnd;
          }
        }
        const endAngle = lineAngle + bendAngle;
        const leftAngle = endAngle + wingAngle;
        const rightAngle = endAngle - wingAngle;
        const x3 = x22 - headLength2 * Math.cos(leftAngle);
        const y3 = y22 - headLength2 * Math.sin(leftAngle);
        const x4 = x22 - headLength2 * Math.cos(rightAngle);
        const y4 = y22 - headLength2 * Math.sin(rightAngle);
        const a2 = r < 1e5 ? `A${r},${r} 0,0,${bendAngle > 0 ? 1 : 0} ` : `L`;
        const h = headLength2 ? `M${x3},${y3}L${x22},${y22}L${x4},${y4}` : "";
        return `M${x12},${y12}${a2}${x22},${y22}${h}`;
      }).call(applyChannelStyles, this, channels)
    ).node();
  }
};
function maybeSweep(sweep = 1) {
  if (typeof sweep === "number") return constant2(Math.sign(sweep));
  if (typeof sweep === "function") return (x12, y12, x22, y22) => Math.sign(sweep(x12, y12, x22, y22));
  switch (keyword(sweep, "sweep", ["+x", "-x", "+y", "-y"])) {
    case "+x":
      return (x12, y12, x22) => ascending(x12, x22);
    case "-x":
      return (x12, y12, x22) => descending(x12, x22);
    case "+y":
      return (x12, y12, x22, y22) => ascending(y12, y22);
    case "-y":
      return (x12, y12, x22, y22) => descending(y12, y22);
  }
}
function pointPointCenter([ax, ay], [bx, by], r, sign3) {
  const dx = bx - ax, dy = by - ay, d = Math.hypot(dx, dy);
  const k2 = sign3 * Math.sqrt(r * r - d * d / 4) / d;
  return [(ax + bx) / 2 - dy * k2, (ay + by) / 2 + dx * k2];
}
function circleCircleIntersect([ax, ay, ar], [bx, by, br], sign3) {
  const dx = bx - ax, dy = by - ay, d = Math.hypot(dx, dy);
  const x3 = (dx * dx + dy * dy - br * br + ar * ar) / (2 * d);
  const y3 = sign3 * Math.sqrt(ar * ar - x3 * x3);
  return [ax + (dx * x3 + dy * y3) / d, ay + (dy * x3 - dx * y3) / d];
}
function arrow(data, { x: x3, x1: x12, x2: x22, y: y3, y1: y12, y2: y22, ...options } = {}) {
  [x12, x22] = maybeSameValue(x3, x12, x22);
  [y12, y22] = maybeSameValue(y3, y12, y22);
  return new Arrow(data, { ...options, x1: x12, x2: x22, y1: y12, y2: y22 });
}

// node_modules/@observablehq/plot/src/marks/bar.js
var barDefaults = {
  ariaLabel: "bar"
};
var AbstractBar = class extends Mark {
  constructor(data, channels, options = {}, defaults22 = barDefaults) {
    super(data, channels, options, defaults22);
    rectInsets(this, options);
    rectRadii(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    const { rx, ry, rx1y1, rx1y2, rx2y1, rx2y2 } = this;
    const x3 = this._x(scales, channels, dimensions);
    const y3 = this._y(scales, channels, dimensions);
    const w = this._width(scales, channels, dimensions);
    const h = this._height(scales, channels, dimensions);
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(this._transform, this, scales).call(
      (g) => g.selectAll().data(index2).enter().call(
        rx1y1 || rx1y2 || rx2y1 || rx2y2 ? (g2) => g2.append("path").call(applyDirectStyles, this).call(applyRoundedRect, x3, y3, add2(x3, w), add2(y3, h), this).call(applyChannelStyles, this, channels) : (g2) => g2.append("rect").call(applyDirectStyles, this).attr("x", x3).attr("width", w).attr("y", y3).attr("height", h).call(applyAttr, "rx", rx).call(applyAttr, "ry", ry).call(applyChannelStyles, this, channels)
      )
    ).node();
  }
  _x(scales, { x: X3 }, { marginLeft }) {
    const { insetLeft } = this;
    return X3 ? (i) => X3[i] + insetLeft : marginLeft + insetLeft;
  }
  _y(scales, { y: Y3 }, { marginTop }) {
    const { insetTop } = this;
    return Y3 ? (i) => Y3[i] + insetTop : marginTop + insetTop;
  }
  _width({ x: x3 }, { x: X3 }, { marginRight, marginLeft, width }) {
    const { insetLeft, insetRight } = this;
    const bandwidth = X3 && x3 ? x3.bandwidth() : width - marginRight - marginLeft;
    return Math.max(0, bandwidth - insetLeft - insetRight);
  }
  _height({ y: y3 }, { y: Y3 }, { marginTop, marginBottom, height }) {
    const { insetTop, insetBottom } = this;
    const bandwidth = Y3 && y3 ? y3.bandwidth() : height - marginTop - marginBottom;
    return Math.max(0, bandwidth - insetTop - insetBottom);
  }
};
function add2(a2, b) {
  return typeof a2 === "function" && typeof b === "function" ? (i) => a2(i) + b(i) : typeof a2 === "function" ? (i) => a2(i) + b : typeof b === "function" ? (i) => a2 + b(i) : a2 + b;
}
var BarX = class extends AbstractBar {
  constructor(data, options = {}, defaults22) {
    const { x1: x12, x2: x22, y: y3 } = options;
    super(
      data,
      {
        x1: { value: x12, scale: "x" },
        x2: { value: x22, scale: "x" },
        y: { value: y3, scale: "y", type: "band", optional: true }
      },
      options,
      defaults22
    );
  }
  _transform(selection2, mark, { x: x3 }) {
    selection2.call(applyTransform, mark, { x: x3 }, 0, 0);
  }
  _x({ x: x3 }, { x1: X13, x2: X23 }, { marginLeft }) {
    const { insetLeft } = this;
    return isCollapsed(x3) ? marginLeft + insetLeft : (i) => Math.min(X13[i], X23[i]) + insetLeft;
  }
  _width({ x: x3 }, { x1: X13, x2: X23 }, { marginRight, marginLeft, width }) {
    const { insetLeft, insetRight } = this;
    return isCollapsed(x3) ? width - marginRight - marginLeft - insetLeft - insetRight : (i) => Math.max(0, Math.abs(X23[i] - X13[i]) - insetLeft - insetRight);
  }
};
var BarY = class extends AbstractBar {
  constructor(data, options = {}, defaults22) {
    const { x: x3, y1: y12, y2: y22 } = options;
    super(
      data,
      {
        y1: { value: y12, scale: "y" },
        y2: { value: y22, scale: "y" },
        x: { value: x3, scale: "x", type: "band", optional: true }
      },
      options,
      defaults22
    );
  }
  _transform(selection2, mark, { y: y3 }) {
    selection2.call(applyTransform, mark, { y: y3 }, 0, 0);
  }
  _y({ y: y3 }, { y1: Y13, y2: Y23 }, { marginTop }) {
    const { insetTop } = this;
    return isCollapsed(y3) ? marginTop + insetTop : (i) => Math.min(Y13[i], Y23[i]) + insetTop;
  }
  _height({ y: y3 }, { y1: Y13, y2: Y23 }, { marginTop, marginBottom, height }) {
    const { insetTop, insetBottom } = this;
    return isCollapsed(y3) ? height - marginTop - marginBottom - insetTop - insetBottom : (i) => Math.max(0, Math.abs(Y23[i] - Y13[i]) - insetTop - insetBottom);
  }
};
function barX(data, options = {}) {
  if (!hasXY(options)) options = { ...options, y: indexOf, x2: identity6 };
  return new BarX(data, maybeStackX(maybeIntervalX(maybeIdentityX(options))));
}
function barY(data, options = {}) {
  if (!hasXY(options)) options = { ...options, x: indexOf, y2: identity6 };
  return new BarY(data, maybeStackY(maybeIntervalY(maybeIdentityY(options))));
}

// node_modules/@observablehq/plot/src/marks/cell.js
var defaults10 = {
  ariaLabel: "cell"
};
var Cell = class extends AbstractBar {
  constructor(data, { x: x3, y: y3, ...options } = {}) {
    super(
      data,
      {
        x: { value: x3, scale: "x", type: "band", optional: true },
        y: { value: y3, scale: "y", type: "band", optional: true }
      },
      options,
      defaults10
    );
  }
  _transform(selection2, mark) {
    selection2.call(applyTransform, mark, {}, 0, 0);
  }
};
function cell(data, { x: x3, y: y3, ...options } = {}) {
  [x3, y3] = maybeTuple(x3, y3);
  return new Cell(data, { ...options, x: x3, y: y3 });
}
function cellX(data, { x: x3 = indexOf, fill, stroke, ...options } = {}) {
  if (fill === void 0 && maybeColorChannel(stroke)[0] === void 0) fill = identity6;
  return new Cell(data, { ...options, x: x3, fill, stroke });
}
function cellY(data, { y: y3 = indexOf, fill, stroke, ...options } = {}) {
  if (fill === void 0 && maybeColorChannel(stroke)[0] === void 0) fill = identity6;
  return new Cell(data, { ...options, y: y3, fill, stroke });
}

// node_modules/@observablehq/plot/src/marks/dot.js
var defaults11 = {
  ariaLabel: "dot",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5
};
function withDefaultSort(options) {
  return options.sort === void 0 && options.reverse === void 0 ? sort2({ channel: "-r" }, options) : options;
}
var Dot = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y: y3, r, rotate, symbol: symbol2 = circle_default3, frameAnchor } = options;
    const [vrotate, crotate] = maybeNumberChannel(rotate, 0);
    const [vsymbol, csymbol] = maybeSymbolChannel(symbol2);
    const [vr, cr] = maybeNumberChannel(r, vsymbol == null ? 3 : 4.5);
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        r: { value: vr, scale: "r", filter: positive, optional: true },
        rotate: { value: vrotate, optional: true },
        symbol: { value: vsymbol, scale: "auto", optional: true }
      },
      withDefaultSort(options),
      defaults11
    );
    this.r = cr;
    this.rotate = crotate;
    this.symbol = csymbol;
    this.frameAnchor = maybeFrameAnchor(frameAnchor);
    const { channels } = this;
    const { symbol: symbolChannel } = channels;
    if (symbolChannel) {
      const { fill: fillChannel, stroke: strokeChannel } = channels;
      symbolChannel.hint = {
        fill: fillChannel ? fillChannel.value === symbolChannel.value ? "color" : "currentColor" : this.fill ?? "currentColor",
        stroke: strokeChannel ? strokeChannel.value === symbolChannel.value ? "color" : "currentColor" : this.stroke ?? "none"
      };
    }
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, r: R, rotate: A5, symbol: S } = channels;
    const { r, rotate, symbol: symbol2 } = this;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    const circle2 = symbol2 === circle_default3;
    const size = R ? void 0 : r * r * Math.PI;
    if (negative(r)) index2 = [];
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      (g) => g.selectAll().data(index2).enter().append(circle2 ? "circle" : "path").call(applyDirectStyles, this).call(
        circle2 ? (selection2) => {
          selection2.attr("cx", X3 ? (i) => X3[i] : cx).attr("cy", Y3 ? (i) => Y3[i] : cy).attr("r", R ? (i) => R[i] : r);
        } : (selection2) => {
          selection2.attr(
            "transform",
            template`translate(${X3 ? (i) => X3[i] : cx},${Y3 ? (i) => Y3[i] : cy})${A5 ? (i) => ` rotate(${A5[i]})` : rotate ? ` rotate(${rotate})` : ``}`
          ).attr(
            "d",
            R && S ? (i) => {
              const p = pathRound();
              S[i].draw(p, R[i] * R[i] * Math.PI);
              return p;
            } : R ? (i) => {
              const p = pathRound();
              symbol2.draw(p, R[i] * R[i] * Math.PI);
              return p;
            } : S ? (i) => {
              const p = pathRound();
              S[i].draw(p, size);
              return p;
            } : (() => {
              const p = pathRound();
              symbol2.draw(p, size);
              return p;
            })()
          );
        }
      ).call(applyChannelStyles, this, channels)
    ).node();
  }
};
function dot(data, { x: x3, y: y3, ...options } = {}) {
  if (options.frameAnchor === void 0) [x3, y3] = maybeTuple(x3, y3);
  return new Dot(data, { ...options, x: x3, y: y3 });
}
function dotX(data, { x: x3 = identity6, ...options } = {}) {
  return new Dot(data, maybeIntervalMidY({ ...options, x: x3 }));
}
function dotY(data, { y: y3 = identity6, ...options } = {}) {
  return new Dot(data, maybeIntervalMidX({ ...options, y: y3 }));
}
function circle(data, options) {
  return dot(data, { ...options, symbol: "circle" });
}
function hexagon(data, options) {
  return dot(data, { ...options, symbol: "hexagon" });
}

// node_modules/@observablehq/plot/src/marks/line.js
var defaults12 = {
  ariaLabel: "line",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  strokeMiterlimit: 1
};
var Line = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y: y3, z, curve, tension } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x" },
        y: { value: y3, scale: "y" },
        z: { value: maybeZ(options), optional: true }
      },
      options,
      defaults12
    );
    this.z = z;
    this.curve = maybeCurveAuto(curve, tension);
    markers(this, options);
  }
  filter(index2) {
    return index2;
  }
  project(channels, values2, context) {
    if (this.curve !== curveAuto) {
      super.project(channels, values2, context);
    }
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: X3, y: Y3 } = channels;
    const { curve } = this;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call(
      (g) => g.selectAll().data(groupIndex(index2, [X3, Y3], this, channels)).enter().append("path").call(applyDirectStyles, this).call(applyGroupedChannelStyles, this, channels).call(applyGroupedMarkers, this, channels, context).attr(
        "d",
        curve === curveAuto && context.projection ? sphereLine(context.path(), X3, Y3) : line_default2().curve(curve).defined((i) => i >= 0).x((i) => X3[i]).y((i) => Y3[i])
      )
    ).node();
  }
};
function sphereLine(path2, X3, Y3) {
  X3 = coerceNumbers(X3);
  Y3 = coerceNumbers(Y3);
  return (I) => {
    let line2 = [];
    const lines = [line2];
    for (const i of I) {
      if (i === -1) {
        line2 = [];
        lines.push(line2);
      } else {
        line2.push([X3[i], Y3[i]]);
      }
    }
    return path2({ type: "MultiLineString", coordinates: lines });
  };
}
function line(data, { x: x3, y: y3, ...options } = {}) {
  [x3, y3] = maybeTuple(x3, y3);
  return new Line(data, { ...options, x: x3, y: y3 });
}
function lineX(data, { x: x3 = identity6, y: y3 = indexOf, ...options } = {}) {
  return new Line(data, maybeDenseIntervalY({ ...options, x: x3, y: y3 }));
}
function lineY(data, { x: x3 = indexOf, y: y3 = identity6, ...options } = {}) {
  return new Line(data, maybeDenseIntervalX({ ...options, x: x3, y: y3 }));
}

// node_modules/@observablehq/plot/src/marks/auto.js
function autoSpec(data, options) {
  options = normalizeOptions(options);
  const { x: x3, y: y3, color: color3, size } = options;
  const X3 = materializeValue(data, x3);
  const Y3 = materializeValue(data, y3);
  const C3 = materializeValue(data, color3);
  const S = materializeValue(data, size);
  let {
    fx,
    fy,
    x: { value: xValue, reduce: xReduce, zero: xZero, ...xOptions },
    y: { value: yValue, reduce: yReduce, zero: yZero, ...yOptions },
    color: { value: colorValue, color: colorColor, reduce: colorReduce },
    size: { value: sizeValue, reduce: sizeReduce },
    // TODO constant radius?
    mark
  } = options;
  if (xReduce === void 0)
    xReduce = yReduce == null && xValue == null && sizeValue == null && yValue != null ? "count" : null;
  if (yReduce === void 0)
    yReduce = xReduce == null && yValue == null && sizeValue == null && xValue != null ? "count" : null;
  if (sizeReduce === void 0 && sizeValue == null && colorReduce == null && xReduce == null && yReduce == null && (xValue == null || isOrdinal(X3)) && (yValue == null || isOrdinal(Y3))) {
    sizeReduce = "count";
  }
  if (xZero === void 0) xZero = isZeroReducer(xReduce) ? true : void 0;
  if (yZero === void 0) yZero = isZeroReducer(yReduce) ? true : void 0;
  if (xValue == null && yValue == null) throw new Error("must specify x or y");
  if (xReduce != null && yValue == null) throw new Error("reducing x requires y");
  if (yReduce != null && xValue == null) throw new Error("reducing y requires x");
  if (mark === void 0) {
    mark = sizeValue != null || sizeReduce != null ? "dot" : isZeroReducer(xReduce) || isZeroReducer(yReduce) || colorReduce != null ? "bar" : xValue != null && yValue != null ? isOrdinal(X3) || isOrdinal(Y3) || xReduce == null && yReduce == null && !isMonotonic(X3) && !isMonotonic(Y3) ? "dot" : "line" : xValue != null || yValue != null ? "rule" : null;
  }
  let Z;
  let colorMode;
  let markImpl;
  switch (mark) {
    case "dot":
      markImpl = dot;
      colorMode = "stroke";
      break;
    case "line":
      markImpl = X3 && Y3 || xReduce != null || yReduce != null ? yZero || yReduce != null || X3 && isMonotonic(X3) ? lineY : xZero || xReduce != null || Y3 && isMonotonic(Y3) ? lineX : line : X3 ? lineX : lineY;
      colorMode = "stroke";
      if (isHighCardinality(C3)) Z = null;
      break;
    case "area":
      markImpl = !(yZero || yReduce != null) && (xZero || xReduce != null || Y3 && isMonotonic(Y3)) ? areaX : areaY;
      colorMode = "fill";
      if (isHighCardinality(C3)) Z = null;
      break;
    case "rule":
      markImpl = X3 ? ruleX : ruleY;
      colorMode = "stroke";
      break;
    case "bar":
      markImpl = xReduce != null ? isOrdinal(Y3) ? isSelectReducer(xReduce) && X3 && isOrdinal(X3) ? cell : barX : rectX : yReduce != null ? isOrdinal(X3) ? isSelectReducer(yReduce) && Y3 && isOrdinal(Y3) ? cell : barY : rectY : colorReduce != null || sizeReduce != null ? X3 && isOrdinal(X3) && Y3 && isOrdinal(Y3) ? cell : X3 && isOrdinal(X3) ? barY : Y3 && isOrdinal(Y3) ? barX : rect : X3 && isNumeric(X3) && !(Y3 && isNumeric(Y3)) ? barX : Y3 && isNumeric(Y3) && !(X3 && isNumeric(X3)) ? barY : cell;
      colorMode = "fill";
      break;
    default:
      throw new Error(`invalid mark: ${mark}`);
  }
  let markOptions2 = {
    fx,
    fy,
    x: X3 ?? void 0,
    // treat null x as undefined for implicit stack
    y: Y3 ?? void 0,
    // treat null y as undefined for implicit stack
    [colorMode]: C3 ?? colorColor,
    z: Z,
    r: S ?? void 0,
    // treat null size as undefined for default constant radius
    tip: true
  };
  let transformImpl;
  let transformOptions = { [colorMode]: colorReduce ?? void 0, r: sizeReduce ?? void 0 };
  if (xReduce != null && yReduce != null) {
    throw new Error(`cannot reduce both x and y`);
  } else if (yReduce != null) {
    transformOptions.y = yReduce;
    transformImpl = isOrdinal(X3) ? groupX : binX;
  } else if (xReduce != null) {
    transformOptions.x = xReduce;
    transformImpl = isOrdinal(Y3) ? groupY : binY;
  } else if (colorReduce != null || sizeReduce != null) {
    if (X3 && Y3) {
      transformImpl = isOrdinal(X3) && isOrdinal(Y3) ? group2 : isOrdinal(X3) ? binY : isOrdinal(Y3) ? binX : bin2;
    } else if (X3) {
      transformImpl = isOrdinal(X3) ? groupX : binX;
    } else if (Y3) {
      transformImpl = isOrdinal(Y3) ? groupY : binY;
    }
  }
  if (transformImpl === bin2 || transformImpl === binX) markOptions2.x = { value: X3, ...xOptions };
  if (transformImpl === bin2 || transformImpl === binY) markOptions2.y = { value: Y3, ...yOptions };
  if (xZero === void 0)
    xZero = X3 && !(transformImpl === bin2 || transformImpl === binX) && (markImpl === barX || markImpl === areaX || markImpl === rectX || markImpl === ruleY);
  if (yZero === void 0)
    yZero = Y3 && !(transformImpl === bin2 || transformImpl === binY) && (markImpl === barY || markImpl === areaY || markImpl === rectY || markImpl === ruleX);
  return {
    fx: fx ?? null,
    fy: fy ?? null,
    x: {
      value: xValue ?? null,
      reduce: xReduce ?? null,
      zero: !!xZero,
      ...xOptions
    },
    y: {
      value: yValue ?? null,
      reduce: yReduce ?? null,
      zero: !!yZero,
      ...yOptions
    },
    color: {
      value: colorValue ?? null,
      reduce: colorReduce ?? null,
      ...colorColor !== void 0 && { color: colorColor }
    },
    size: {
      value: sizeValue ?? null,
      reduce: sizeReduce ?? null
    },
    mark,
    markImpl: implNames[markImpl],
    markOptions: markOptions2,
    transformImpl: implNames[transformImpl],
    transformOptions,
    colorMode
  };
}
function auto(data, options) {
  const spec = autoSpec(data, options);
  const {
    fx,
    fy,
    x: { zero: xZero },
    y: { zero: yZero },
    markOptions: markOptions2,
    transformOptions,
    colorMode
  } = spec;
  const markImpl = impls[spec.markImpl];
  const transformImpl = impls[spec.transformImpl];
  const frames = fx != null || fy != null ? frame2({ strokeOpacity: 0.1 }) : null;
  const rules = [xZero ? ruleX([0]) : null, yZero ? ruleY([0]) : null];
  const mark = markImpl(data, transformImpl ? transformImpl(transformOptions, markOptions2) : markOptions2);
  return colorMode === "stroke" ? marks(frames, rules, mark) : marks(frames, mark, rules);
}
function isMonotonic(values2) {
  let previous;
  let previousOrder;
  for (const value of values2) {
    if (value == null) continue;
    if (previous === void 0) {
      previous = value;
      continue;
    }
    const order = Math.sign(ascending(previous, value));
    if (!order) continue;
    if (previousOrder !== void 0 && order !== previousOrder) return false;
    previous = value;
    previousOrder = order;
  }
  return true;
}
function normalizeOptions({ x: x3, y: y3, color: color3, size, fx, fy, mark } = {}) {
  if (!isOptions(x3)) x3 = makeOptions(x3);
  if (!isOptions(y3)) y3 = makeOptions(y3);
  if (!isOptions(color3)) color3 = isColor(color3) ? { color: color3 } : makeOptions(color3);
  if (!isOptions(size)) size = makeOptions(size);
  if (isOptions(fx)) ({ value: fx } = makeOptions(fx));
  if (isOptions(fy)) ({ value: fy } = makeOptions(fy));
  if (mark != null) mark = `${mark}`.toLowerCase();
  return { x: x3, y: y3, color: color3, size, fx, fy, mark };
}
function materializeValue(data, options) {
  const V = valueof(data, options.value);
  if (V) V.label = labelof(options.value);
  return V;
}
function makeOptions(value) {
  return isReducer(value) ? { reduce: value } : { value };
}
function isZeroReducer(reduce2) {
  return /^(?:distinct|count|sum|proportion)$/i.test(reduce2);
}
function isSelectReducer(reduce2) {
  return /^(?:first|last|mode)$/i.test(reduce2);
}
function isReducer(reduce2) {
  if (reduce2 == null) return false;
  if (typeof reduce2.reduceIndex === "function") return true;
  if (typeof reduce2.reduce === "function" && isObject(reduce2)) return true;
  if (/^p\d{2}$/i.test(reduce2)) return true;
  switch (`${reduce2}`.toLowerCase()) {
    case "first":
    case "last":
    case "count":
    case "distinct":
    case "sum":
    case "proportion":
    case "proportion-facet":
    // TODO remove me?
    case "deviation":
    case "min":
    case "min-index":
    // TODO remove me?
    case "max":
    case "max-index":
    // TODO remove me?
    case "mean":
    case "median":
    case "variance":
    case "mode":
      return true;
  }
  return false;
}
function isHighCardinality(value) {
  return value ? new InternSet(value).size > value.length >> 1 : false;
}
var impls = {
  dot,
  line,
  lineX,
  lineY,
  areaX,
  areaY,
  ruleX,
  ruleY,
  barX,
  barY,
  rect,
  rectX,
  rectY,
  cell,
  bin: bin2,
  binX,
  binY,
  group: group2,
  groupX,
  groupY
};
var implNames = Object.fromEntries(Object.entries(impls).map(([name, impl]) => [impl, name]));

// node_modules/@observablehq/plot/src/transforms/map.js
function mapX(mapper, options = {}) {
  let { x: x3, x1: x12, x2: x22 } = options;
  if (x3 === void 0 && x12 === void 0 && x22 === void 0) options = { ...options, x: x3 = identity6 };
  const outputs = {};
  if (x3 != null) outputs.x = mapper;
  if (x12 != null) outputs.x1 = mapper;
  if (x22 != null) outputs.x2 = mapper;
  return map5(outputs, options);
}
function mapY(mapper, options = {}) {
  let { y: y3, y1: y12, y2: y22 } = options;
  if (y3 === void 0 && y12 === void 0 && y22 === void 0) options = { ...options, y: y3 = identity6 };
  const outputs = {};
  if (y3 != null) outputs.y = mapper;
  if (y12 != null) outputs.y1 = mapper;
  if (y22 != null) outputs.y2 = mapper;
  return map5(outputs, options);
}
function map5(outputs = {}, options = {}) {
  const z = maybeZ(options);
  const channels = Object.entries(outputs).map(([key, map6]) => {
    const input = maybeInput(key, options);
    if (input == null) throw new Error(`missing channel: ${key}`);
    const [output, setOutput] = column(input);
    return { key, input, output, setOutput, map: maybeMap(map6) };
  });
  return {
    ...basic(options, (data, facets) => {
      const Z = valueof(data, z);
      const X3 = channels.map(({ input }) => valueof(data, input));
      const MX = channels.map(({ setOutput }) => setOutput(new Array(data.length)));
      for (const facet of facets) {
        for (const I of Z ? group(facet, (i) => Z[i]).values() : [facet]) {
          channels.forEach(({ map: map6 }, i) => map6.mapIndex(I, X3[i], MX[i]));
        }
      }
      return { data, facets };
    }),
    ...Object.fromEntries(channels.map(({ key, output }) => [key, output]))
  };
}
function maybeMap(map6) {
  if (map6 == null) throw new Error("missing map");
  if (typeof map6.mapIndex === "function") return map6;
  if (typeof map6.map === "function" && isObject(map6)) return mapMap(map6);
  if (typeof map6 === "function") return mapFunction(taker(map6));
  switch (`${map6}`.toLowerCase()) {
    case "cumsum":
      return mapCumsum;
    case "rank":
      return mapFunction((I, V) => rank(I, (i) => V[i]));
    case "quantile":
      return mapFunction((I, V) => rankQuantile(I, (i) => V[i]));
  }
  throw new Error(`invalid map: ${map6}`);
}
function mapMap(map6) {
  console.warn("deprecated map interface; implement mapIndex instead.");
  return { mapIndex: map6.map.bind(map6) };
}
function rankQuantile(I, f) {
  const n = count(I, f) - 1;
  return rank(I, f).map((r) => r / n);
}
function mapFunction(f) {
  return {
    mapIndex(I, S, T) {
      const M2 = f(I, S);
      if (M2.length !== I.length) throw new Error("map function returned a mismatched length");
      for (let i = 0, n = I.length; i < n; ++i) T[I[i]] = M2[i];
    }
  };
}
var mapCumsum = {
  mapIndex(I, S, T) {
    let sum4 = 0;
    for (const i of I) T[i] = sum4 += S[i];
  }
};

// node_modules/@observablehq/plot/src/transforms/window.js
function windowX(windowOptions = {}, options) {
  if (arguments.length === 1) options = windowOptions;
  return mapX(window2(windowOptions), options);
}
function windowY(windowOptions = {}, options) {
  if (arguments.length === 1) options = windowOptions;
  return mapY(window2(windowOptions), options);
}
function window2(options = {}) {
  if (typeof options === "number") options = { k: options };
  let { k: k2, reduce: reduce2, shift, anchor, strict } = options;
  if (anchor === void 0 && shift !== void 0) {
    anchor = maybeShift(shift);
    warn(`Warning: the shift option is deprecated; please use anchor "${anchor}" instead.`);
  }
  if (!((k2 = Math.floor(k2)) > 0)) throw new Error(`invalid k: ${k2}`);
  return maybeReduce2(reduce2)(k2, maybeAnchor3(anchor, k2), strict);
}
function maybeAnchor3(anchor = "middle", k2) {
  switch (`${anchor}`.toLowerCase()) {
    case "middle":
      return k2 - 1 >> 1;
    case "start":
      return 0;
    case "end":
      return k2 - 1;
  }
  throw new Error(`invalid anchor: ${anchor}`);
}
function maybeShift(shift) {
  switch (`${shift}`.toLowerCase()) {
    case "centered":
      return "middle";
    case "leading":
      return "start";
    case "trailing":
      return "end";
  }
  throw new Error(`invalid shift: ${shift}`);
}
function maybeReduce2(reduce2 = "mean") {
  if (typeof reduce2 === "string") {
    if (/^p\d{2}$/i.test(reduce2)) return reduceAccessor2(percentile(reduce2));
    switch (reduce2.toLowerCase()) {
      case "deviation":
        return reduceAccessor2(deviation);
      case "max":
        return reduceArray((I, V) => max(I, (i) => V[i]));
      case "mean":
        return reduceMean;
      case "median":
        return reduceAccessor2(median);
      case "min":
        return reduceArray((I, V) => min(I, (i) => V[i]));
      case "mode":
        return reduceArray((I, V) => mode(I, (i) => V[i]));
      case "sum":
        return reduceSum2;
      case "variance":
        return reduceAccessor2(variance);
      case "difference":
        return reduceDifference;
      case "ratio":
        return reduceRatio;
      case "first":
        return reduceFirst2;
      case "last":
        return reduceLast2;
    }
  }
  if (typeof reduce2 !== "function") throw new Error(`invalid reduce: ${reduce2}`);
  return reduceArray(taker(reduce2));
}
function reduceAccessor2(f) {
  return (k2, s2, strict) => strict ? {
    mapIndex(I, S, T) {
      const v2 = (i) => S[i] == null ? NaN : +S[i];
      let nans = 0;
      for (let i = 0; i < k2 - 1; ++i) if (isNaN(v2(i))) ++nans;
      for (let i = 0, n = I.length - k2 + 1; i < n; ++i) {
        if (isNaN(v2(i + k2 - 1))) ++nans;
        T[I[i + s2]] = nans === 0 ? f(subarray(I, i, i + k2), v2) : NaN;
        if (isNaN(v2(i))) --nans;
      }
    }
  } : {
    mapIndex(I, S, T) {
      const v2 = (i) => S[i] == null ? NaN : +S[i];
      for (let i = -s2; i < 0; ++i) {
        T[I[i + s2]] = f(subarray(I, 0, i + k2), v2);
      }
      for (let i = 0, n = I.length - s2; i < n; ++i) {
        T[I[i + s2]] = f(subarray(I, i, i + k2), v2);
      }
    }
  };
}
function reduceArray(f) {
  return (k2, s2, strict) => strict ? {
    mapIndex(I, S, T) {
      let count3 = 0;
      for (let i = 0; i < k2 - 1; ++i) count3 += defined(S[I[i]]);
      for (let i = 0, n = I.length - k2 + 1; i < n; ++i) {
        count3 += defined(S[I[i + k2 - 1]]);
        if (count3 === k2) T[I[i + s2]] = f(subarray(I, i, i + k2), S);
        count3 -= defined(S[I[i]]);
      }
    }
  } : {
    mapIndex(I, S, T) {
      for (let i = -s2; i < 0; ++i) {
        T[I[i + s2]] = f(subarray(I, 0, i + k2), S);
      }
      for (let i = 0, n = I.length - s2; i < n; ++i) {
        T[I[i + s2]] = f(subarray(I, i, i + k2), S);
      }
    }
  };
}
function reduceSum2(k2, s2, strict) {
  return strict ? {
    mapIndex(I, S, T) {
      let nans = 0;
      let sum4 = 0;
      for (let i = 0; i < k2 - 1; ++i) {
        const v2 = S[I[i]];
        if (v2 === null || isNaN(v2)) ++nans;
        else sum4 += +v2;
      }
      for (let i = 0, n = I.length - k2 + 1; i < n; ++i) {
        const a2 = S[I[i]];
        const b = S[I[i + k2 - 1]];
        if (b === null || isNaN(b)) ++nans;
        else sum4 += +b;
        T[I[i + s2]] = nans === 0 ? sum4 : NaN;
        if (a2 === null || isNaN(a2)) --nans;
        else sum4 -= +a2;
      }
    }
  } : {
    mapIndex(I, S, T) {
      let sum4 = 0;
      const n = I.length;
      for (let i = 0, j = Math.min(n, k2 - s2 - 1); i < j; ++i) {
        sum4 += +S[I[i]] || 0;
      }
      for (let i = -s2, j = n - s2; i < j; ++i) {
        sum4 += +S[I[i + k2 - 1]] || 0;
        T[I[i + s2]] = sum4;
        sum4 -= +S[I[i]] || 0;
      }
    }
  };
}
function reduceMean(k2, s2, strict) {
  if (strict) {
    const sum4 = reduceSum2(k2, s2, strict);
    return {
      mapIndex(I, S, T) {
        sum4.mapIndex(I, S, T);
        for (let i = 0, n = I.length - k2 + 1; i < n; ++i) {
          T[I[i + s2]] /= k2;
        }
      }
    };
  } else {
    return {
      mapIndex(I, S, T) {
        let sum4 = 0;
        let count3 = 0;
        const n = I.length;
        for (let i = 0, j = Math.min(n, k2 - s2 - 1); i < j; ++i) {
          let v2 = S[I[i]];
          if (v2 !== null && !isNaN(v2 = +v2)) sum4 += v2, ++count3;
        }
        for (let i = -s2, j = n - s2; i < j; ++i) {
          let a2 = S[I[i + k2 - 1]];
          let b = S[I[i]];
          if (a2 !== null && !isNaN(a2 = +a2)) sum4 += a2, ++count3;
          T[I[i + s2]] = sum4 / count3;
          if (b !== null && !isNaN(b = +b)) sum4 -= b, --count3;
        }
      }
    };
  }
}
function firstDefined(S, I, i, k2) {
  for (let j = i + k2; i < j; ++i) {
    const v2 = S[I[i]];
    if (defined(v2)) return v2;
  }
}
function lastDefined(S, I, i, k2) {
  for (let j = i + k2 - 1; j >= i; --j) {
    const v2 = S[I[j]];
    if (defined(v2)) return v2;
  }
}
function firstNumber(S, I, i, k2) {
  for (let j = i + k2; i < j; ++i) {
    let v2 = S[I[i]];
    if (v2 !== null && !isNaN(v2 = +v2)) return v2;
  }
}
function lastNumber(S, I, i, k2) {
  for (let j = i + k2 - 1; j >= i; --j) {
    let v2 = S[I[j]];
    if (v2 !== null && !isNaN(v2 = +v2)) return v2;
  }
}
function reduceDifference(k2, s2, strict) {
  return strict ? {
    mapIndex(I, S, T) {
      for (let i = 0, n = I.length - k2; i < n; ++i) {
        const a2 = S[I[i]];
        const b = S[I[i + k2 - 1]];
        T[I[i + s2]] = a2 === null || b === null ? NaN : b - a2;
      }
    }
  } : {
    mapIndex(I, S, T) {
      for (let i = -s2, n = I.length - k2 + s2 + 1; i < n; ++i) {
        T[I[i + s2]] = lastNumber(S, I, i, k2) - firstNumber(S, I, i, k2);
      }
    }
  };
}
function reduceRatio(k2, s2, strict) {
  return strict ? {
    mapIndex(I, S, T) {
      for (let i = 0, n = I.length - k2; i < n; ++i) {
        const a2 = S[I[i]];
        const b = S[I[i + k2 - 1]];
        T[I[i + s2]] = a2 === null || b === null ? NaN : b / a2;
      }
    }
  } : {
    mapIndex(I, S, T) {
      for (let i = -s2, n = I.length - k2 + s2 + 1; i < n; ++i) {
        T[I[i + s2]] = lastNumber(S, I, i, k2) / firstNumber(S, I, i, k2);
      }
    }
  };
}
function reduceFirst2(k2, s2, strict) {
  return strict ? {
    mapIndex(I, S, T) {
      for (let i = 0, n = I.length - k2; i < n; ++i) {
        T[I[i + s2]] = S[I[i]];
      }
    }
  } : {
    mapIndex(I, S, T) {
      for (let i = -s2, n = I.length - k2 + s2 + 1; i < n; ++i) {
        T[I[i + s2]] = firstDefined(S, I, i, k2);
      }
    }
  };
}
function reduceLast2(k2, s2, strict) {
  return strict ? {
    mapIndex(I, S, T) {
      for (let i = 0, n = I.length - k2; i < n; ++i) {
        T[I[i + s2]] = S[I[i + k2 - 1]];
      }
    }
  } : {
    mapIndex(I, S, T) {
      for (let i = -s2, n = I.length - k2 + s2 + 1; i < n; ++i) {
        T[I[i + s2]] = lastDefined(S, I, i, k2);
      }
    }
  };
}

// node_modules/@observablehq/plot/src/marks/bollinger.js
var defaults13 = {
  n: 20,
  k: 2,
  color: "currentColor",
  opacity: 0.2,
  strict: true,
  anchor: "end"
};
function bollingerX(data, {
  x: x3 = identity6,
  y: y3,
  k: k2 = defaults13.k,
  color: color3 = defaults13.color,
  opacity: opacity2 = defaults13.opacity,
  fill = color3,
  fillOpacity = opacity2,
  stroke = color3,
  strokeOpacity,
  strokeWidth,
  ...options
} = {}) {
  return marks(
    isNoneish(fill) ? null : areaX(
      data,
      map5(
        { x1: bollinger({ k: -k2, ...options }), x2: bollinger({ k: k2, ...options }) },
        { x1: x3, x2: x3, y: y3, fill, fillOpacity, ...options }
      )
    ),
    isNoneish(stroke) ? null : lineX(data, map5({ x: bollinger(options) }, { x: x3, y: y3, stroke, strokeOpacity, strokeWidth, ...options }))
  );
}
function bollingerY(data, {
  x: x3,
  y: y3 = identity6,
  k: k2 = defaults13.k,
  color: color3 = defaults13.color,
  opacity: opacity2 = defaults13.opacity,
  fill = color3,
  fillOpacity = opacity2,
  stroke = color3,
  strokeOpacity,
  strokeWidth,
  ...options
} = {}) {
  return marks(
    isNoneish(fill) ? null : areaY(
      data,
      map5(
        { y1: bollinger({ k: -k2, ...options }), y2: bollinger({ k: k2, ...options }) },
        { x: x3, y1: y3, y2: y3, fill, fillOpacity, ...options }
      )
    ),
    isNoneish(stroke) ? null : lineY(data, map5({ y: bollinger(options) }, { x: x3, y: y3, stroke, strokeOpacity, strokeWidth, ...options }))
  );
}
function bollinger({ n = defaults13.n, k: k2 = 0, strict = defaults13.strict, anchor = defaults13.anchor } = {}) {
  return window2({ k: n, reduce: (Y3) => mean(Y3) + k2 * (deviation(Y3) || 0), strict, anchor });
}

// node_modules/@observablehq/plot/src/marks/tick.js
var defaults14 = {
  ariaLabel: "tick",
  fill: null,
  stroke: "currentColor"
};
var AbstractTick = class extends Mark {
  constructor(data, channels, options) {
    super(data, channels, options, defaults14);
    markers(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(this._transform, this, scales).call(
      (g) => g.selectAll().data(index2).enter().append("line").call(applyDirectStyles, this).attr("x1", this._x1(scales, channels, dimensions)).attr("x2", this._x2(scales, channels, dimensions)).attr("y1", this._y1(scales, channels, dimensions)).attr("y2", this._y2(scales, channels, dimensions)).call(applyChannelStyles, this, channels).call(applyMarkers, this, channels, context)
    ).node();
  }
};
var TickX = class extends AbstractTick {
  constructor(data, options = {}) {
    const { x: x3, y: y3, inset = 0, insetTop = inset, insetBottom = inset } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x" },
        y: { value: y3, scale: "y", type: "band", optional: true }
      },
      options
    );
    this.insetTop = number5(insetTop);
    this.insetBottom = number5(insetBottom);
  }
  _transform(selection2, mark, { x: x3 }) {
    selection2.call(applyTransform, mark, { x: x3 }, offset, 0);
  }
  _x1(scales, { x: X3 }) {
    return (i) => X3[i];
  }
  _x2(scales, { x: X3 }) {
    return (i) => X3[i];
  }
  _y1({ y: y3 }, { y: Y3 }, { marginTop }) {
    const { insetTop } = this;
    return Y3 && y3 ? (i) => Y3[i] + insetTop : marginTop + insetTop;
  }
  _y2({ y: y3 }, { y: Y3 }, { height, marginBottom }) {
    const { insetBottom } = this;
    return Y3 && y3 ? (i) => Y3[i] + y3.bandwidth() - insetBottom : height - marginBottom - insetBottom;
  }
};
var TickY = class extends AbstractTick {
  constructor(data, options = {}) {
    const { x: x3, y: y3, inset = 0, insetRight = inset, insetLeft = inset } = options;
    super(
      data,
      {
        y: { value: y3, scale: "y" },
        x: { value: x3, scale: "x", type: "band", optional: true }
      },
      options
    );
    this.insetRight = number5(insetRight);
    this.insetLeft = number5(insetLeft);
  }
  _transform(selection2, mark, { y: y3 }) {
    selection2.call(applyTransform, mark, { y: y3 }, 0, offset);
  }
  _x1({ x: x3 }, { x: X3 }, { marginLeft }) {
    const { insetLeft } = this;
    return X3 && x3 ? (i) => X3[i] + insetLeft : marginLeft + insetLeft;
  }
  _x2({ x: x3 }, { x: X3 }, { width, marginRight }) {
    const { insetRight } = this;
    return X3 && x3 ? (i) => X3[i] + x3.bandwidth() - insetRight : width - marginRight - insetRight;
  }
  _y1(scales, { y: Y3 }) {
    return (i) => Y3[i];
  }
  _y2(scales, { y: Y3 }) {
    return (i) => Y3[i];
  }
};
function tickX(data, { x: x3 = identity6, ...options } = {}) {
  return new TickX(data, { ...options, x: x3 });
}
function tickY(data, { y: y3 = identity6, ...options } = {}) {
  return new TickY(data, { ...options, y: y3 });
}

// node_modules/@observablehq/plot/src/marks/box.js
function boxX(data, {
  x: x3 = identity6,
  y: y3 = null,
  r,
  fill = "#ccc",
  fillOpacity,
  stroke = "currentColor",
  strokeOpacity,
  strokeWidth = 2,
  sort: sort3,
  ...options
} = {}) {
  const group3 = y3 != null ? groupY : groupZ;
  return marks(
    ruleY(data, group3({ x1: loqr1, x2: hiqr2 }, { x: x3, y: y3, stroke, strokeOpacity, ...options })),
    barX(data, group3({ x1: "p25", x2: "p75" }, { x: x3, y: y3, fill, fillOpacity, ...options })),
    tickX(data, group3({ x: "p50" }, { x: x3, y: y3, stroke, strokeOpacity, strokeWidth, sort: sort3, ...options })),
    dot(data, map5({ x: oqr }, { x: x3, y: y3, z: y3, r, stroke, strokeOpacity, ...options }))
  );
}
function boxY(data, {
  y: y3 = identity6,
  x: x3 = null,
  r,
  fill = "#ccc",
  fillOpacity,
  stroke = "currentColor",
  strokeOpacity,
  strokeWidth = 2,
  sort: sort3,
  ...options
} = {}) {
  const group3 = x3 != null ? groupX : groupZ;
  return marks(
    ruleX(data, group3({ y1: loqr1, y2: hiqr2 }, { x: x3, y: y3, stroke, strokeOpacity, ...options })),
    barY(data, group3({ y1: "p25", y2: "p75" }, { x: x3, y: y3, fill, fillOpacity, ...options })),
    tickY(data, group3({ y: "p50" }, { x: x3, y: y3, stroke, strokeOpacity, strokeWidth, sort: sort3, ...options })),
    dot(data, map5({ y: oqr }, { x: x3, y: y3, z: x3, r, stroke, strokeOpacity, ...options }))
  );
}
function oqr(values2) {
  const r1 = loqr1(values2);
  const r2 = hiqr2(values2);
  return values2.map((v2) => v2 < r1 || v2 > r2 ? v2 : NaN);
}
function loqr1(values2) {
  const lo = quartile1(values2) * 2.5 - quartile3(values2) * 1.5;
  return min(values2, (d) => d >= lo ? d : NaN);
}
function hiqr2(values2) {
  const hi = quartile3(values2) * 2.5 - quartile1(values2) * 1.5;
  return max(values2, (d) => d <= hi ? d : NaN);
}
function quartile1(values2) {
  return quantile(values2, 0.25);
}
function quartile3(values2) {
  return quantile(values2, 0.75);
}

// node_modules/@observablehq/plot/src/marks/raster.js
var defaults15 = {
  ariaLabel: "raster",
  stroke: null,
  pixelSize: 1
};
function number6(input, name) {
  const x3 = +input;
  if (isNaN(x3)) throw new Error(`invalid ${name}: ${input}`);
  return x3;
}
function integer(input, name) {
  const x3 = Math.floor(input);
  if (isNaN(x3)) throw new Error(`invalid ${name}: ${input}`);
  return x3;
}
var AbstractRaster = class extends Mark {
  constructor(data, channels, options = {}, defaults22) {
    let {
      width,
      height,
      x: x3,
      y: y3,
      x1: x12 = x3 == null ? 0 : void 0,
      y1: y12 = y3 == null ? 0 : void 0,
      x2: x22 = x3 == null ? width : void 0,
      y2: y22 = y3 == null ? height : void 0,
      pixelSize = defaults22.pixelSize,
      blur: blur3 = 0,
      interpolate
    } = options;
    if (width != null) width = integer(width, "width");
    if (height != null) height = integer(height, "height");
    if (x12 != null) x12 = number6(x12, "x1");
    if (y12 != null) y12 = number6(y12, "y1");
    if (x22 != null) x22 = number6(x22, "x2");
    if (y22 != null) y22 = number6(y22, "y2");
    if (x3 == null && (x12 == null || x22 == null)) throw new Error("missing x");
    if (y3 == null && (y12 == null || y22 == null)) throw new Error("missing y");
    if (data != null && width != null && height != null) {
      if (x3 === void 0 && x12 != null && x22 != null) x3 = denseX(x12, x22, width, height);
      if (y3 === void 0 && y12 != null && y22 != null) y3 = denseY(y12, y22, width, height);
    }
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        x1: { value: x12 == null ? null : [x12], scale: "x", optional: true, filter: null },
        y1: { value: y12 == null ? null : [y12], scale: "y", optional: true, filter: null },
        x2: { value: x22 == null ? null : [x22], scale: "x", optional: true, filter: null },
        y2: { value: y22 == null ? null : [y22], scale: "y", optional: true, filter: null },
        ...channels
      },
      options,
      defaults22
    );
    this.width = width;
    this.height = height;
    this.pixelSize = number6(pixelSize, "pixelSize");
    this.blur = number6(blur3, "blur");
    this.interpolate = x3 == null || y3 == null ? null : maybeInterpolate(interpolate);
  }
};
var Raster = class extends AbstractRaster {
  constructor(data, options = {}) {
    const { imageRendering } = options;
    if (data == null) {
      const { fill, fillOpacity } = options;
      if (maybeNumberChannel(fillOpacity)[0] !== void 0) options = sampler("fillOpacity", options);
      if (maybeColorChannel(fill)[0] !== void 0) options = sampler("fill", options);
    }
    super(data, void 0, options, defaults15);
    this.imageRendering = impliedString(imageRendering, "auto");
  }
  // Ignore the color scale, so the fill channel is returned unscaled.
  scale(channels, { color: color3, ...scales }, context) {
    return super.scale(channels, scales, context);
  }
  render(index2, scales, values2, dimensions, context) {
    var _a;
    const color3 = scales[(_a = values2.channels.fill) == null ? void 0 : _a.scale] ?? ((x3) => x3);
    const { x: X3, y: Y3 } = values2;
    const { document: document2 } = context;
    const [x12, y12, x22, y22] = renderBounds(values2, dimensions, context);
    const dx = x22 - x12;
    const dy = y22 - y12;
    const { pixelSize: k2, width: w = Math.round(Math.abs(dx) / k2), height: h = Math.round(Math.abs(dy) / k2) } = this;
    const n = w * h;
    let { fill: F, fillOpacity: FO } = values2;
    let offset2 = 0;
    if (this.interpolate) {
      const kx2 = w / dx;
      const ky2 = h / dy;
      const IX = map4(X3, (x3) => (x3 - x12) * kx2, Float64Array);
      const IY = map4(Y3, (y3) => (y3 - y12) * ky2, Float64Array);
      if (F) F = this.interpolate(index2, w, h, IX, IY, F);
      if (FO) FO = this.interpolate(index2, w, h, IX, IY, FO);
    } else if (this.data == null && index2) offset2 = index2.fi * n;
    const canvas = document2.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const context2d = canvas.getContext("2d");
    const image2 = context2d.createImageData(w, h);
    const imageData = image2.data;
    let { r, g, b } = rgb(this.fill) ?? { r: 0, g: 0, b: 0 };
    let a2 = (this.fillOpacity ?? 1) * 255;
    for (let i = 0; i < n; ++i) {
      const j = i << 2;
      if (F) {
        const fi = color3(F[i + offset2]);
        if (fi == null) {
          imageData[j + 3] = 0;
          continue;
        }
        ({ r, g, b } = rgb(fi));
      }
      if (FO) a2 = FO[i + offset2] * 255;
      imageData[j + 0] = r;
      imageData[j + 1] = g;
      imageData[j + 2] = b;
      imageData[j + 3] = a2;
    }
    if (this.blur > 0) blurImage(image2, this.blur);
    context2d.putImageData(image2, 0, 0);
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call(
      (g2) => g2.append("image").attr("transform", `translate(${x12},${y12}) scale(${Math.sign(x22 - x12)},${Math.sign(y22 - y12)})`).attr("width", Math.abs(dx)).attr("height", Math.abs(dy)).attr("preserveAspectRatio", "none").call(applyAttr, "image-rendering", this.imageRendering).call(applyDirectStyles, this).attr("xlink:href", canvas.toDataURL())
    ).node();
  }
};
function maybeTuples(k2, data, options) {
  if (arguments.length < 3) options = data, data = null;
  let { x: x3, y: y3, [k2]: z, ...rest } = options;
  if (x3 === void 0 && y3 === void 0 && isTuples(data)) {
    x3 = first, y3 = second2;
    if (z === void 0) z = third;
  }
  return [data, { ...rest, x: x3, y: y3, [k2]: z }];
}
function raster() {
  const [data, options] = maybeTuples("fill", ...arguments);
  return new Raster(
    data,
    data == null || options.fill !== void 0 || options.fillOpacity !== void 0 ? options : { ...options, fill: identity6 }
  );
}
function renderBounds({ x1: x12, y1: y12, x2: x22, y2: y22 }, dimensions, { projection: projection3 }) {
  const { width, height, marginTop, marginRight, marginBottom, marginLeft } = dimensions;
  return [
    x12 && projection3 == null ? x12[0] : marginLeft,
    y12 && projection3 == null ? y12[0] : marginTop,
    x22 && projection3 == null ? x22[0] : width - marginRight,
    y22 && projection3 == null ? y22[0] : height - marginBottom
  ];
}
function rasterBounds({ x1: x12, y1: y12, x2: x22, y2: y22 }, scales, dimensions, context) {
  const channels = {};
  if (x12) channels.x1 = x12;
  if (y12) channels.y1 = y12;
  if (x22) channels.x2 = x22;
  if (y22) channels.y2 = y22;
  return renderBounds(valueObject(channels, scales), dimensions, context);
}
function sampler(name, options = {}) {
  const { [name]: value } = options;
  if (typeof value !== "function") throw new Error(`invalid ${name}: not a function`);
  return initializer({ ...options, [name]: void 0 }, function(data, facets, channels, scales, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    if (!x3) throw new Error("missing scale: x");
    if (!y3) throw new Error("missing scale: y");
    const [x12, y12, x22, y22] = rasterBounds(channels, scales, dimensions, context);
    const dx = x22 - x12;
    const dy = y22 - y12;
    const { pixelSize: k2 } = this;
    const { width: w = Math.round(Math.abs(dx) / k2), height: h = Math.round(Math.abs(dy) / k2) } = options;
    const V = new Array(w * h * (facets ? facets.length : 1));
    const kx2 = dx / w;
    const ky2 = dy / h;
    let i = 0;
    for (const facet of facets ?? [void 0]) {
      for (let yi = 0.5; yi < h; ++yi) {
        for (let xi = 0.5; xi < w; ++xi, ++i) {
          V[i] = value(x3.invert(x12 + xi * kx2), y3.invert(y12 + yi * ky2), facet);
        }
      }
    }
    return { data: V, facets, channels: { [name]: { value: V, scale: "auto" } } };
  });
}
function maybeInterpolate(interpolate) {
  if (typeof interpolate === "function") return interpolate;
  if (interpolate == null) return interpolateNone;
  switch (`${interpolate}`.toLowerCase()) {
    case "none":
      return interpolateNone;
    case "nearest":
      return interpolateNearest;
    case "barycentric":
      return interpolatorBarycentric();
    case "random-walk":
      return interpolatorRandomWalk();
  }
  throw new Error(`invalid interpolate: ${interpolate}`);
}
function interpolateNone(index2, width, height, X3, Y3, V) {
  const W = new Array(width * height);
  for (const i of index2) {
    if (X3[i] < 0 || X3[i] >= width || Y3[i] < 0 || Y3[i] >= height) continue;
    W[Math.floor(Y3[i]) * width + Math.floor(X3[i])] = V[i];
  }
  return W;
}
function interpolatorBarycentric({ random = lcg(42) } = {}) {
  return (index2, width, height, X3, Y3, V) => {
    const { points, triangles, hull: hull2 } = Delaunay.from(
      index2,
      (i) => X3[i],
      (i) => Y3[i]
    );
    const W = new V.constructor(width * height).fill(NaN);
    const S = new Uint8Array(width * height);
    const mix = mixer(V, random);
    for (let i = 0; i < triangles.length; i += 3) {
      const ta = triangles[i];
      const tb = triangles[i + 1];
      const tc = triangles[i + 2];
      const Ax = points[2 * ta];
      const Bx = points[2 * tb];
      const Cx = points[2 * tc];
      const Ay = points[2 * ta + 1];
      const By = points[2 * tb + 1];
      const Cy = points[2 * tc + 1];
      const x12 = Math.min(Ax, Bx, Cx);
      const x22 = Math.max(Ax, Bx, Cx);
      const y12 = Math.min(Ay, By, Cy);
      const y22 = Math.max(Ay, By, Cy);
      const z = (By - Cy) * (Ax - Cx) + (Ay - Cy) * (Cx - Bx);
      if (!z) continue;
      const va = V[index2[ta]];
      const vb = V[index2[tb]];
      const vc = V[index2[tc]];
      for (let x3 = Math.floor(x12); x3 < x22; ++x3) {
        for (let y3 = Math.floor(y12); y3 < y22; ++y3) {
          if (x3 < 0 || x3 >= width || y3 < 0 || y3 >= height) continue;
          const xp = x3 + 0.5;
          const yp = y3 + 0.5;
          const s2 = Math.sign(z);
          const ga = (By - Cy) * (xp - Cx) + (yp - Cy) * (Cx - Bx);
          if (ga * s2 < 0) continue;
          const gb = (Cy - Ay) * (xp - Cx) + (yp - Cy) * (Ax - Cx);
          if (gb * s2 < 0) continue;
          const gc = z - (ga + gb);
          if (gc * s2 < 0) continue;
          const i2 = x3 + width * y3;
          W[i2] = mix(va, ga / z, vb, gb / z, vc, gc / z, x3, y3);
          S[i2] = 1;
        }
      }
    }
    extrapolateBarycentric(W, S, X3, Y3, V, width, height, hull2, index2, mix);
    return W;
  };
}
function extrapolateBarycentric(W, S, X3, Y3, V, width, height, hull2, index2, mix) {
  X3 = Float64Array.from(hull2, (i) => X3[index2[i]]);
  Y3 = Float64Array.from(hull2, (i) => Y3[index2[i]]);
  V = Array.from(hull2, (i) => V[index2[i]]);
  const n = X3.length;
  const rays = Array.from({ length: n }, (_, j) => ray(j, X3, Y3));
  let k2 = 0;
  for (let y3 = 0; y3 < height; ++y3) {
    const yp = y3 + 0.5;
    for (let x3 = 0; x3 < width; ++x3) {
      const i = x3 + width * y3;
      if (!S[i]) {
        const xp = x3 + 0.5;
        for (let l = 0; l < n; ++l) {
          const j = (n + k2 + (l % 2 ? (l + 1) / 2 : -l / 2)) % n;
          if (rays[j](xp, yp)) {
            const t = segmentProject(X3.at(j - 1), Y3.at(j - 1), X3[j], Y3[j], xp, yp);
            W[i] = mix(V.at(j - 1), t, V[j], 1 - t, V[j], 0, x3, y3);
            k2 = j;
            break;
          }
        }
      }
    }
  }
}
function segmentProject(x12, y12, x22, y22, x3, y3) {
  const dx = x22 - x12;
  const dy = y22 - y12;
  const a2 = dx * (x22 - x3) + dy * (y22 - y3);
  const b = dx * (x3 - x12) + dy * (y3 - y12);
  return a2 > 0 && b > 0 ? a2 / (a2 + b) : +(a2 > b);
}
function cross2(xa, ya, xb, yb) {
  return xa * yb - xb * ya;
}
function ray(j, X3, Y3) {
  const n = X3.length;
  const xc = X3.at(j - 2);
  const yc = Y3.at(j - 2);
  const xa = X3.at(j - 1);
  const ya = Y3.at(j - 1);
  const xb = X3[j];
  const yb = Y3[j];
  const xd = X3.at(j + 1 - n);
  const yd = Y3.at(j + 1 - n);
  const dxab = xa - xb;
  const dyab = ya - yb;
  const dxca = xc - xa;
  const dyca = yc - ya;
  const dxbd = xb - xd;
  const dybd = yb - yd;
  const hab = Math.hypot(dxab, dyab);
  const hca = Math.hypot(dxca, dyca);
  const hbd = Math.hypot(dxbd, dybd);
  return (x3, y3) => {
    const dxa = x3 - xa;
    const dya = y3 - ya;
    const dxb = x3 - xb;
    const dyb = y3 - yb;
    return cross2(dxa, dya, dxb, dyb) > -1e-6 && cross2(dxa, dya, dxab, dyab) * hca - cross2(dxa, dya, dxca, dyca) * hab > -1e-6 && cross2(dxb, dyb, dxbd, dybd) * hab - cross2(dxb, dyb, dxab, dyab) * hbd <= 0;
  };
}
function interpolateNearest(index2, width, height, X3, Y3, V) {
  const W = new V.constructor(width * height);
  const delaunay = Delaunay.from(
    index2,
    (i) => X3[i],
    (i) => Y3[i]
  );
  let iy, ix;
  for (let y3 = 0.5, k2 = 0; y3 < height; ++y3) {
    ix = iy;
    for (let x3 = 0.5; x3 < width; ++x3, ++k2) {
      ix = delaunay.find(x3, y3, ix);
      if (x3 === 0.5) iy = ix;
      W[k2] = V[index2[ix]];
    }
  }
  return W;
}
function interpolatorRandomWalk({ random = lcg(42), minDistance = 0.5, maxSteps = 2 } = {}) {
  return (index2, width, height, X3, Y3, V) => {
    const W = new V.constructor(width * height);
    const delaunay = Delaunay.from(
      index2,
      (i) => X3[i],
      (i) => Y3[i]
    );
    let iy, ix, iw;
    for (let y3 = 0.5, k2 = 0; y3 < height; ++y3) {
      ix = iy;
      for (let x3 = 0.5; x3 < width; ++x3, ++k2) {
        let cx = x3;
        let cy = y3;
        iw = ix = delaunay.find(cx, cy, ix);
        if (x3 === 0.5) iy = ix;
        let distance;
        let step = 0;
        while ((distance = Math.hypot(X3[index2[iw]] - cx, Y3[index2[iw]] - cy)) > minDistance && step < maxSteps) {
          const angle = random(x3, y3, step) * 2 * Math.PI;
          cx += Math.cos(angle) * distance;
          cy += Math.sin(angle) * distance;
          iw = delaunay.find(cx, cy, iw);
          ++step;
        }
        W[k2] = V[index2[iw]];
      }
    }
    return W;
  };
}
function blend(a2, ca3, b, cb, c4, cc2) {
  return ca3 * a2 + cb * b + cc2 * c4;
}
function pick(random) {
  return (a2, ca3, b, cb, c4, cc2, x3, y3) => {
    const u4 = random(x3, y3);
    return u4 < ca3 ? a2 : u4 < ca3 + cb ? b : c4;
  };
}
function mixer(F, random) {
  return isNumeric(F) || isTemporal(F) ? blend : pick(random);
}
function denseX(x12, x22, width) {
  return {
    transform(data) {
      const n = data.length;
      const X3 = new Float64Array(n);
      const kx2 = (x22 - x12) / width;
      const x06 = x12 + kx2 / 2;
      for (let i = 0; i < n; ++i) X3[i] = i % width * kx2 + x06;
      return X3;
    }
  };
}
function denseY(y12, y22, width, height) {
  return {
    transform(data) {
      const n = data.length;
      const Y3 = new Float64Array(n);
      const ky2 = (y22 - y12) / height;
      const y06 = y12 + ky2 / 2;
      for (let i = 0; i < n; ++i) Y3[i] = Math.floor(i / width) % height * ky2 + y06;
      return Y3;
    }
  };
}

// node_modules/@observablehq/plot/src/marks/contour.js
var defaults16 = {
  ariaLabel: "contour",
  fill: "none",
  stroke: "currentColor",
  strokeMiterlimit: 1,
  pixelSize: 2
};
var Contour = class extends AbstractRaster {
  constructor(data, { smooth = true, value, ...options } = {}) {
    const channels = styles({}, options, defaults16);
    if (value === void 0) {
      for (const key in channels) {
        if (channels[key].value != null) {
          if (value !== void 0) throw new Error("ambiguous contour value");
          value = options[key];
          options[key] = "value";
        }
      }
    }
    if (value != null) {
      const v2 = { transform: (D3) => D3.map((d) => d.value), label: labelof(value) };
      for (const key in channels) {
        if (options[key] === "value") {
          options[key] = v2;
        }
      }
    }
    if (data == null) {
      if (value == null) throw new Error("missing contour value");
      options = sampler("value", { value, ...options });
      value = null;
    } else {
      let { interpolate } = options;
      if (value === void 0) value = identity6;
      if (interpolate === void 0) options.interpolate = "nearest";
    }
    super(data, { value: { value, optional: true } }, contourGeometry(options), defaults16);
    const contourChannels = { geometry: { value: identity6 } };
    for (const key in this.channels) {
      const channel = this.channels[key];
      const { scale: scale3 } = channel;
      if (scale3 === "x" || scale3 === "y" || key === "value") continue;
      contourChannels[key] = channel;
      delete this.channels[key];
    }
    this.contourChannels = contourChannels;
    this.smooth = !!smooth;
  }
  filter(index2, { x: x3, y: y3, value, ...channels }, values2) {
    return super.filter(index2, channels, values2);
  }
  render(index2, scales, channels, dimensions, context) {
    const { geometry: G } = channels;
    const path2 = path_default();
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call((g) => {
      g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).attr("d", (i) => path2(G[i])).call(applyChannelStyles, this, channels);
    }).node();
  }
};
function contourGeometry({ thresholds, interval: interval2, ...options }) {
  thresholds = maybeThresholds(thresholds, interval2, thresholdSturges);
  return initializer(options, function(data, facets, channels, scales, dimensions, context) {
    const [x12, y12, x22, y22] = rasterBounds(channels, scales, dimensions, context);
    const dx = x22 - x12;
    const dy = y22 - y12;
    const { pixelSize: k2, width: w = Math.round(Math.abs(dx) / k2), height: h = Math.round(Math.abs(dy) / k2) } = this;
    const kx2 = w / dx;
    const ky2 = h / dy;
    const V = channels.value.value;
    const VV = [];
    if (this.interpolate) {
      const { x: X3, y: Y3 } = applyPosition(channels, scales, context);
      const IX = map4(X3, (x3) => (x3 - x12) * kx2, Float64Array);
      const IY = map4(Y3, (y3) => (y3 - y12) * ky2, Float64Array);
      const ichannels = [channels.x, channels.y, channels.value];
      const ivalues = [IX, IY, V];
      for (const facet of facets) {
        const index2 = this.filter(facet, ichannels, ivalues);
        VV.push(this.interpolate(index2, w, h, IX, IY, V));
      }
    } else if (facets) {
      const n = w * h;
      const m = facets.length;
      for (let i = 0; i < m; ++i) VV.push(V.slice(i * n, i * n + n));
    } else {
      VV.push(V);
    }
    if (this.blur > 0) for (const V2 of VV) blur2({ data: V2, width: w, height: h }, this.blur);
    const T = maybeTicks(thresholds, V, ...finiteExtent(VV));
    if (T === null) throw new Error(`unsupported thresholds: ${thresholds}`);
    const { contour: contour2 } = contours_default().size([w, h]).smooth(this.smooth);
    const contourData = [];
    const contourFacets = [];
    for (const V2 of VV) {
      contourFacets.push(range(contourData.length, contourData.push(...map4(T, (t) => contour2(V2, t)))));
    }
    for (const { coordinates } of contourData) {
      for (const rings of coordinates) {
        for (const ring of rings) {
          for (const point6 of ring) {
            point6[0] = point6[0] / kx2 + x12;
            point6[1] = point6[1] / ky2 + y12;
          }
        }
      }
    }
    return {
      data: contourData,
      facets: contourFacets,
      channels: createChannels(this.contourChannels, contourData)
    };
  });
}
function maybeTicks(thresholds, V, min4, max5) {
  if (typeof (thresholds == null ? void 0 : thresholds.range) === "function") return thresholds.range(thresholds.floor(min4), max5);
  if (typeof thresholds === "function") thresholds = thresholds(V, min4, max5);
  if (typeof thresholds !== "number") return arrayify2(thresholds);
  const tz = ticks(...nice(min4, max5, thresholds), thresholds);
  while (tz[tz.length - 1] >= max5) tz.pop();
  while (tz[1] < min4) tz.shift();
  return tz;
}
function contour() {
  return new Contour(...maybeTuples("value", ...arguments));
}
function finiteExtent(VV) {
  return [min(VV, (V) => min(V, finite3)), max(VV, (V) => max(V, finite3))];
}
function finite3(x3) {
  return isFinite(x3) ? x3 : NaN;
}

// node_modules/@observablehq/plot/src/marks/crosshair.js
function crosshair(data, options) {
  return crosshairK(pointer, data, options);
}
function crosshairX(data, options = {}) {
  return crosshairK(pointerX, data, options);
}
function crosshairY(data, options = {}) {
  return crosshairK(pointerY, data, options);
}
function crosshairK(pointer2, data, options = {}) {
  const { x: x3, y: y3, maxRadius } = options;
  const p = pointer2({ px: x3, py: y3, maxRadius });
  const M2 = [];
  if (x3 != null) M2.push(ruleX(data, ruleOptions("x", { ...p, inset: -6 }, options)));
  if (y3 != null) M2.push(ruleY(data, ruleOptions("y", { ...p, inset: -6 }, options)));
  if (x3 != null) M2.push(text(data, textOptions("x", { ...p, dy: 9, frameAnchor: "bottom", lineAnchor: "top" }, options)));
  if (y3 != null) M2.push(text(data, textOptions("y", { ...p, dx: -9, frameAnchor: "left", textAnchor: "end" }, options)));
  for (const m of M2) m.ariaLabel = `crosshair ${m.ariaLabel}`;
  return marks(...M2);
}
function markOptions(k2, { channels: pointerChannels, ...pointerOptions }, { facet, facetAnchor, fx, fy, [k2]: p, channels, transform: transform2, initializer: initializer2 }) {
  return {
    ...pointerOptions,
    facet,
    facetAnchor,
    fx,
    fy,
    [k2]: p,
    channels: { ...pointerChannels, ...channels },
    transform: transform2,
    initializer: pxpy(k2, initializer2)
  };
}
function pxpy(k2, i) {
  if (i == null) return i;
  return function(data, facets, { x: x12, y: y12, px, py, ...c1 }, ...args) {
    const { channels: { x: x3, y: y3, ...c4 } = {}, ...rest } = i.call(this, data, facets, { ...c1, x: px, y: py }, ...args);
    return {
      channels: {
        ...c4,
        ...x3 && { px: x3, ...k2 === "x" && { x: x3 } },
        ...y3 && { py: y3, ...k2 === "y" && { y: y3 } }
      },
      ...rest
    };
  };
}
function ruleOptions(k2, pointerOptions, options) {
  const {
    color: color3 = "currentColor",
    opacity: opacity2 = 0.2,
    ruleStroke: stroke = color3,
    ruleStrokeOpacity: strokeOpacity = opacity2,
    ruleStrokeWidth: strokeWidth
  } = options;
  return {
    ...markOptions(k2, pointerOptions, options),
    stroke,
    strokeOpacity,
    strokeWidth
  };
}
function textOptions(k2, pointerOptions, options) {
  const {
    color: color3 = "currentColor",
    textFill: fill = color3,
    textFillOpacity: fillOpacity,
    textStroke: stroke = "var(--plot-background)",
    textStrokeOpacity: strokeOpacity,
    textStrokeWidth: strokeWidth = 5
  } = options;
  return {
    ...markOptions(k2, pointerOptions, textChannel(k2, options)),
    fill,
    fillOpacity,
    stroke,
    strokeOpacity,
    strokeWidth
  };
}
function textChannel(source, options) {
  return initializer(options, (data, facets, channels) => {
    var _a;
    return { channels: { text: { value: (_a = getSource(channels, source)) == null ? void 0 : _a.value } } };
  });
}

// node_modules/@observablehq/plot/src/marks/delaunay.js
var delaunayLinkDefaults = {
  ariaLabel: "delaunay link",
  fill: "none",
  stroke: "currentColor",
  strokeMiterlimit: 1
};
var delaunayMeshDefaults = {
  ariaLabel: "delaunay mesh",
  fill: null,
  stroke: "currentColor",
  strokeOpacity: 0.2
};
var hullDefaults = {
  ariaLabel: "hull",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeMiterlimit: 1
};
var voronoiDefaults = {
  ariaLabel: "voronoi",
  fill: "none",
  stroke: "currentColor",
  strokeMiterlimit: 1
};
var voronoiMeshDefaults = {
  ariaLabel: "voronoi mesh",
  fill: null,
  stroke: "currentColor",
  strokeOpacity: 0.2
};
var DelaunayLink = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y: y3, z, curve, tension } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        z: { value: z, optional: true }
      },
      options,
      delaunayLinkDefaults
    );
    this.curve = maybeCurve(curve, tension);
    markers(this, options);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, z: Z } = channels;
    const { curve } = this;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    const xi = X3 ? (i) => X3[i] : constant2(cx);
    const yi = Y3 ? (i) => Y3[i] : constant2(cy);
    const mark = this;
    function links(index3) {
      let i = -1;
      const newIndex = [];
      const newChannels = {};
      for (const k2 in channels) newChannels[k2] = [];
      const X13 = [];
      const X23 = [];
      const Y13 = [];
      const Y23 = [];
      function link4(ti, tj) {
        ti = index3[ti];
        tj = index3[tj];
        newIndex.push(++i);
        X13[i] = xi(ti);
        Y13[i] = yi(ti);
        X23[i] = xi(tj);
        Y23[i] = yi(tj);
        for (const k2 in channels) newChannels[k2].push(channels[k2][tj]);
      }
      const { halfedges, hull: hull2, triangles } = Delaunay.from(index3, xi, yi);
      for (let i2 = 0; i2 < halfedges.length; ++i2) {
        const j = halfedges[i2];
        if (j > i2) link4(triangles[i2], triangles[j]);
      }
      for (let i2 = 0; i2 < hull2.length; ++i2) {
        link4(hull2[i2], hull2[(i2 + 1) % hull2.length]);
      }
      select_default2(this).selectAll().data(newIndex).enter().append("path").call(applyDirectStyles, mark).attr("d", (i2) => {
        const p = pathRound();
        const c4 = curve(p);
        c4.lineStart();
        c4.point(X13[i2], Y13[i2]);
        c4.point(X23[i2], Y23[i2]);
        c4.lineEnd();
        return p;
      }).call(applyChannelStyles, mark, newChannels).call(applyMarkers, mark, newChannels, context);
    }
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      Z ? (g) => g.selectAll().data(group(index2, (i) => Z[i]).values()).enter().append("g").each(links) : (g) => g.datum(index2).each(links)
    ).node();
  }
};
var AbstractDelaunayMark = class extends Mark {
  constructor(data, options = {}, defaults22, zof = ({ z }) => z) {
    const { x: x3, y: y3 } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        z: { value: zof(options), optional: true }
      },
      options,
      defaults22
    );
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, z: Z } = channels;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    const xi = X3 ? (i) => X3[i] : constant2(cx);
    const yi = Y3 ? (i) => Y3[i] : constant2(cy);
    const mark = this;
    function mesh(index3) {
      const delaunay = Delaunay.from(index3, xi, yi);
      select_default2(this).append("path").datum(index3[0]).call(applyDirectStyles, mark).attr("d", mark._render(delaunay, dimensions)).call(applyChannelStyles, mark, channels);
    }
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      Z ? (g) => g.selectAll().data(group(index2, (i) => Z[i]).values()).enter().append("g").each(mesh) : (g) => g.datum(index2).each(mesh)
    ).node();
  }
};
var DelaunayMesh = class extends AbstractDelaunayMark {
  constructor(data, options = {}) {
    super(data, options, delaunayMeshDefaults);
    this.fill = "none";
  }
  _render(delaunay) {
    return delaunay.render();
  }
};
var Hull = class extends AbstractDelaunayMark {
  constructor(data, options = {}) {
    super(data, options, hullDefaults, maybeZ);
  }
  _render(delaunay) {
    return delaunay.renderHull();
  }
};
var Voronoi2 = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y: y3, z } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        z: { value: z, optional: true }
      },
      initializer(options, function(data2, facets, channels, scales, dimensions, context) {
        let { x: X3, y: Y3, z: Z } = channels;
        ({ x: X3, y: Y3 } = applyPosition(channels, scales, context));
        Z = Z == null ? void 0 : Z.value;
        const C3 = new Array((X3 ?? Y3).length).fill(null);
        const [cx, cy] = applyFrameAnchor(this, dimensions);
        const xi = X3 ? (i) => X3[i] : constant2(cx);
        const yi = Y3 ? (i) => Y3[i] : constant2(cy);
        for (let I of facets) {
          if (X3) I = I.filter((i) => defined(xi(i)));
          if (Y3) I = I.filter((i) => defined(yi(i)));
          for (const [, J] of maybeGroup(I, Z)) {
            const delaunay = Delaunay.from(J, xi, yi);
            const voronoi2 = voronoiof(delaunay, dimensions);
            for (let i = 0, n = J.length; i < n; ++i) {
              C3[J[i]] = voronoi2.renderCell(i);
            }
          }
        }
        return { data: data2, facets, channels: { cells: { value: C3 } } };
      }),
      voronoiDefaults
    );
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, cells: C3 } = channels;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call((g) => {
      g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).attr("d", (i) => C3[i]).call(applyChannelStyles, this, channels);
    }).node();
  }
};
var VoronoiMesh = class extends AbstractDelaunayMark {
  constructor(data, options) {
    super(data, options, voronoiMeshDefaults);
    this.fill = "none";
  }
  _render(delaunay, dimensions) {
    return voronoiof(delaunay, dimensions).render();
  }
};
function voronoiof(delaunay, dimensions) {
  const { width, height, marginTop, marginRight, marginBottom, marginLeft } = dimensions;
  return delaunay.voronoi([marginLeft, marginTop, width - marginRight, height - marginBottom]);
}
function delaunayMark(DelaunayMark, data, { x: x3, y: y3, ...options } = {}) {
  [x3, y3] = maybeTuple(x3, y3);
  return new DelaunayMark(data, { ...options, x: x3, y: y3 });
}
function delaunayLink(data, options) {
  return delaunayMark(DelaunayLink, data, options);
}
function delaunayMesh(data, options) {
  return delaunayMark(DelaunayMesh, data, options);
}
function hull(data, options) {
  return delaunayMark(Hull, data, options);
}
function voronoi(data, { x: x3, y: y3, initializer: initializer2, ...options } = {}) {
  return delaunayMark(Voronoi2, data, { ...basic({ ...options, x: x3, y: y3 }, exclusiveFacets), initializer: initializer2 });
}
function voronoiMesh(data, options) {
  return delaunayMark(VoronoiMesh, data, options);
}

// node_modules/@observablehq/plot/src/marks/density.js
var defaults17 = {
  ariaLabel: "density",
  fill: "none",
  stroke: "currentColor",
  strokeMiterlimit: 1
};
var Density = class extends Mark {
  constructor(data, { x: x3, y: y3, z, weight, fill, stroke, ...options } = {}) {
    const fillDensity = isDensity(fill) && (fill = "currentColor", true);
    const strokeDensity = isDensity(stroke) && (stroke = "currentColor", true);
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        z: { value: maybeZ({ z, fill, stroke }), optional: true },
        weight: { value: weight, optional: true }
      },
      densityInitializer({ ...options, fill, stroke }, fillDensity, strokeDensity),
      defaults17
    );
    if (fillDensity) this.fill = void 0;
    if (strokeDensity) this.stroke = void 0;
    this.z = z;
  }
  filter(index2) {
    return index2;
  }
  render(index2, scales, channels, dimensions, context) {
    const { contours } = channels;
    const path2 = path_default();
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, {}).call(
      (g) => g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).call(applyChannelStyles, this, channels).attr("d", (i) => path2(contours[i]))
    ).node();
  }
};
function density(data, { x: x3, y: y3, ...options } = {}) {
  [x3, y3] = maybeTuple(x3, y3);
  return new Density(data, { ...options, x: x3, y: y3 });
}
var dropChannels = /* @__PURE__ */ new Set(["x", "y", "z", "weight"]);
function densityInitializer(options, fillDensity, strokeDensity) {
  const k2 = 100;
  let { bandwidth, thresholds } = options;
  bandwidth = bandwidth === void 0 ? 20 : +bandwidth;
  thresholds = thresholds === void 0 ? 20 : typeof (thresholds == null ? void 0 : thresholds[Symbol.iterator]) === "function" ? coerceNumbers(thresholds) : +thresholds;
  return initializer(options, function(data, facets, channels, scales, dimensions, context) {
    var _a;
    const W = channels.weight ? coerceNumbers(channels.weight.value) : null;
    const Z = (_a = channels.z) == null ? void 0 : _a.value;
    const { z } = this;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    const { width, height } = dimensions;
    const { x: X3, y: Y3 } = applyPosition(channels, scales, context);
    const newChannels = Object.fromEntries(
      Object.entries(channels).filter(([key]) => !dropChannels.has(key)).map(([key, channel]) => [key, { ...channel, value: [] }])
    );
    const FD = fillDensity && [];
    const SD = strokeDensity && [];
    const density2 = density_default().x(X3 ? (i) => X3[i] : cx).y(Y3 ? (i) => Y3[i] : cy).weight(W ? (i) => W[i] : 1).size([width, height]).bandwidth(bandwidth);
    const facetsContours = [];
    for (const facet of facets) {
      const facetContours = [];
      facetsContours.push(facetContours);
      for (const index2 of Z ? groupZ2(facet, Z, z) : [facet]) {
        const contour2 = density2.contours(index2);
        facetContours.push([index2, contour2]);
      }
    }
    let T = thresholds;
    if (!(T instanceof TypedArray)) {
      let maxValue = 0;
      for (const facetContours of facetsContours) {
        for (const [, contour2] of facetContours) {
          const max5 = contour2.max;
          if (max5 > maxValue) maxValue = max5;
        }
      }
      T = Float64Array.from({ length: thresholds - 1 }, (_, i) => maxValue * k2 * (i + 1) / thresholds);
    }
    const newFacets = [];
    const contours = [];
    for (const facetContours of facetsContours) {
      const newFacet = [];
      newFacets.push(newFacet);
      for (const [index2, contour2] of facetContours) {
        for (const t of T) {
          newFacet.push(contours.length);
          contours.push(contour2(t / k2));
          if (FD) FD.push(t);
          if (SD) SD.push(t);
          for (const key in newChannels) {
            newChannels[key].value.push(channels[key].value[index2[0]]);
          }
        }
      }
    }
    if (FD) FD.push(0);
    if (SD) SD.push(0);
    return {
      data,
      facets: newFacets,
      channels: {
        ...newChannels,
        ...FD && { fill: { value: FD, scale: "color" } },
        ...SD && { stroke: { value: SD, scale: "color" } },
        contours: { value: contours }
      }
    };
  });
}
function isDensity(value) {
  return /^density$/i.test(value);
}

// node_modules/@observablehq/plot/src/marks/difference.js
function differenceX(data, options) {
  return differenceK("x", data, options);
}
function differenceY(data, options) {
  return differenceK("y", data, options);
}
function differenceK(k2, data, {
  x1: x12,
  x2: x22,
  y1: y12,
  y2: y22,
  x: x3 = x12 === void 0 && x22 === void 0 ? k2 === "y" ? indexOf : identity6 : void 0,
  y: y3 = y12 === void 0 && y22 === void 0 ? k2 === "x" ? indexOf : identity6 : void 0,
  fill,
  // ignored
  positiveFill = "#3ca951",
  negativeFill = "#4269d0",
  fillOpacity = 1,
  positiveFillOpacity = fillOpacity,
  negativeFillOpacity = fillOpacity,
  stroke,
  strokeOpacity,
  z = maybeColorChannel(stroke)[0],
  clip,
  // optional additional clip for area
  tip: tip2,
  render,
  ...options
} = {}) {
  [x12, x22] = memoTuple(x3, x12, x22);
  [y12, y22] = memoTuple(y3, y12, y22);
  if (x12 === x22 && y12 === y22) {
    if (k2 === "y") y12 = memo(0);
    else x12 = memo(0);
  }
  ({ tip: tip2 } = withTip({ tip: tip2 }, k2 === "y" ? "x" : "y"));
  return marks(
    !isNoneish(positiveFill) ? Object.assign(
      area(data, {
        x1: x12,
        x2: x22,
        y1: y12,
        y2: y22,
        z,
        fill: positiveFill,
        fillOpacity: positiveFillOpacity,
        render: composeRender(render, clipDifference(k2, true)),
        clip,
        ...options
      }),
      { ariaLabel: "positive difference" }
    ) : null,
    !isNoneish(negativeFill) ? Object.assign(
      area(data, {
        x1: x12,
        x2: x22,
        y1: y12,
        y2: y22,
        z,
        fill: negativeFill,
        fillOpacity: negativeFillOpacity,
        render: composeRender(render, clipDifference(k2, false)),
        clip,
        ...options
      }),
      { ariaLabel: "negative difference" }
    ) : null,
    line(data, {
      x: x22,
      y: y22,
      z,
      stroke,
      strokeOpacity,
      tip: tip2,
      clip: true,
      ...options
    })
  );
}
function memoTuple(x3, x12, x22) {
  if (x12 === void 0 && x22 === void 0) {
    x12 = x22 = memo(x3);
  } else if (x12 === void 0) {
    x22 = memo(x22);
    x12 = x3 === void 0 ? x22 : memo(x3);
  } else if (x22 === void 0) {
    x12 = memo(x12);
    x22 = x3 === void 0 ? x12 : memo(x3);
  } else {
    x12 = memo(x12);
    x22 = memo(x22);
  }
  return [x12, x22];
}
function memo(v2) {
  let V;
  const { value, label = labelof(value) } = maybeValue(v2);
  return { transform: (data) => V || (V = valueof(data, value)), label };
}
function clipDifference(k2, positive2) {
  const f = k2 === "x" ? "y" : "x";
  const f1 = `${f}1`;
  const f2 = `${f}2`;
  const k1 = `${k2}1`;
  const k22 = `${k2}2`;
  return (index2, scales, channels, dimensions, context, next) => {
    const { [f1]: F1, [f2]: F2 } = channels;
    const K1 = new Float32Array(F1.length);
    const K2 = new Float32Array(F2.length);
    const m = dimensions[k2 === "y" ? "height" : "width"];
    (positive2 === inferScaleOrder(scales[k2]) < 0 ? K1 : K2).fill(m);
    const oc = next(index2, scales, { ...channels, [f2]: F1, [k22]: K2 }, dimensions, context);
    const og = next(index2, scales, { ...channels, [f1]: F2, [k1]: K1 }, dimensions, context);
    const c4 = oc.querySelector("g") ?? oc;
    const g = og.querySelector("g") ?? og;
    for (let i = 0; c4.firstChild; i += 2) {
      const id2 = getClipId();
      const clipPath = create2("svg:clipPath", context).attr("id", id2).node();
      clipPath.appendChild(c4.firstChild);
      g.childNodes[i].setAttribute("clip-path", `url(#${id2})`);
      g.insertBefore(clipPath, g.childNodes[i]);
    }
    return og;
  };
}

// node_modules/@observablehq/plot/src/transforms/centroid.js
function centroid({ geometry = identity6, ...options } = {}) {
  const getG = memoize1((data) => valueof(data, geometry));
  return initializer(
    // Suppress defaults for x and y since they will be computed by the initializer.
    // Propagate the (memoized) geometry channel in case it’s still needed.
    { ...options, x: null, y: null, geometry: { transform: getG } },
    (data, facets, channels, scales, dimensions, context) => {
      const G = getG(data);
      const n = G.length;
      const X3 = new Float64Array(n);
      const Y3 = new Float64Array(n);
      const { centroid: centroid2 } = context.path();
      for (let i = 0; i < n; ++i) [X3[i], Y3[i]] = centroid2(G[i]);
      return {
        data,
        facets,
        channels: { x: { value: X3, scale: null, source: null }, y: { value: Y3, scale: null, source: null } }
      };
    }
  );
}
function geoCentroid({ geometry = identity6, ...options } = {}) {
  const getG = memoize1((data) => valueof(data, geometry));
  const getC = memoize1((data) => valueof(getG(data), centroid_default));
  return {
    ...options,
    x: { transform: (data) => Float64Array.from(getC(data), ([x3]) => x3) },
    y: { transform: (data) => Float64Array.from(getC(data), ([, y3]) => y3) },
    geometry: { transform: getG }
  };
}

// node_modules/@observablehq/plot/src/marks/geo.js
var defaults18 = {
  ariaLabel: "geo",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  strokeMiterlimit: 1
};
var Geo = class extends Mark {
  constructor(data, options = {}) {
    const [vr, cr] = maybeNumberChannel(options.r, 3);
    super(
      data,
      {
        x: { value: options.tip ? options.x : null, scale: "x", optional: true },
        y: { value: options.tip ? options.y : null, scale: "y", optional: true },
        r: { value: vr, scale: "r", filter: positive, optional: true },
        geometry: { value: options.geometry, scale: "projection" }
      },
      withDefaultSort(options),
      defaults18
    );
    this.r = cr;
  }
  render(index2, scales, channels, dimensions, context) {
    const { geometry: G, r: R } = channels;
    const path2 = context.path();
    const { r } = this;
    if (negative(r)) index2 = [];
    else if (r !== void 0) path2.pointRadius(r);
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call((g) => {
      g.selectAll().data(index2).enter().append("path").call(applyDirectStyles, this).attr("d", R ? (i) => path2.pointRadius(R[i])(G[i]) : (i) => path2(G[i])).call(applyChannelStyles, this, channels);
    }).node();
  }
};
function geo(data, options = {}) {
  if (options.tip && options.x === void 0 && options.y === void 0) options = centroid(options);
  else if (options.geometry === void 0) options = { ...options, geometry: identity6 };
  return new Geo(data, options);
}
function sphere2({ strokeWidth = 1.5, ...options } = {}) {
  return geo({ type: "Sphere" }, { strokeWidth, ...options });
}
function graticule2({ strokeOpacity = 0.1, ...options } = {}) {
  return geo(graticule10(), { strokeOpacity, ...options });
}

// node_modules/@observablehq/plot/src/transforms/hexbin.js
var ox = 0.5;
var oy = 0;
function hexbin(outputs = { fill: "count" }, { binWidth, ...options } = {}) {
  const { z } = options;
  binWidth = binWidth === void 0 ? 20 : number5(binWidth);
  outputs = maybeGroupOutputs(outputs, options);
  if (hasOutput(outputs, "fill")) options.channels = { ...options.channels, fill: { value: [] } };
  if (options.symbol === void 0) options.symbol = "hexagon";
  if (options.r === void 0 && !hasOutput(outputs, "r")) options.r = binWidth / 2;
  return initializer(options, (data, facets, channels, scales, _, context) => {
    let { x: X3, y: Y3, z: Z, fill: F, stroke: S, symbol: Q } = channels;
    if (X3 === void 0) throw new Error("missing channel: x");
    if (Y3 === void 0) throw new Error("missing channel: y");
    ({ x: X3, y: Y3 } = applyPosition(channels, scales, context));
    Z = Z ? Z.value : valueof(data, z);
    F = F == null ? void 0 : F.value;
    S = S == null ? void 0 : S.value;
    Q = Q == null ? void 0 : Q.value;
    const G = maybeSubgroup(outputs, { z: Z, fill: F, stroke: S, symbol: Q });
    const GZ = Z && [];
    const GF = F && [];
    const GS = S && [];
    const GQ = Q && [];
    const binFacets = [];
    const BX = [];
    const BY = [];
    let i = -1;
    for (const o of outputs) o.initialize(data);
    for (const facet of facets) {
      const binFacet = [];
      for (const o of outputs) o.scope("facet", facet);
      for (const [f, I] of maybeGroup(facet, G)) {
        for (const { index: b, extent: extent3 } of hbin(data, I, X3, Y3, binWidth)) {
          binFacet.push(++i);
          BX.push(extent3.x);
          BY.push(extent3.y);
          if (Z) GZ.push(G === Z ? f : Z[b[0]]);
          if (F) GF.push(G === F ? f : F[b[0]]);
          if (S) GS.push(G === S ? f : S[b[0]]);
          if (Q) GQ.push(G === Q ? f : Q[b[0]]);
          for (const o of outputs) o.reduce(b, extent3);
        }
      }
      binFacets.push(binFacet);
    }
    const sx = channels.x.scale;
    const sy = channels.y.scale;
    const binChannels = {
      x: { value: BX, source: scales[sx] ? { value: map4(BX, scales[sx].invert), scale: sx } : null },
      y: { value: BY, source: scales[sy] ? { value: map4(BY, scales[sy].invert), scale: sy } : null },
      ...Z && { z: { value: GZ } },
      ...F && { fill: { value: GF, scale: "auto" } },
      ...S && { stroke: { value: GS, scale: "auto" } },
      ...Q && { symbol: { value: GQ, scale: "auto" } },
      ...Object.fromEntries(
        outputs.map(({ name, output }) => [
          name,
          {
            scale: "auto",
            label: output.label,
            radius: name === "r" ? binWidth / 2 : void 0,
            value: output.transform()
          }
        ])
      )
    };
    return { data, facets: binFacets, channels: binChannels };
  });
}
function hbin(data, I, X3, Y3, dx) {
  const dy = dx * (1.5 / sqrt35);
  const bins = /* @__PURE__ */ new Map();
  for (const i of I) {
    let px = X3[i], py = Y3[i];
    if (isNaN(px) || isNaN(py)) continue;
    let pj = Math.round(py = (py - oy) / dy), pi7 = Math.round(px = (px - ox) / dx - (pj & 1) / 2), py1 = py - pj;
    if (Math.abs(py1) * 3 > 1) {
      let px1 = px - pi7, pi22 = pi7 + (px < pi7 ? -1 : 1) / 2, pj2 = pj + (py < pj ? -1 : 1), px2 = px - pi22, py2 = py - pj2;
      if (px1 * px1 + py1 * py1 > px2 * px2 + py2 * py2) pi7 = pi22 + (pj & 1 ? 1 : -1) / 2, pj = pj2;
    }
    const key = `${pi7},${pj}`;
    let bin3 = bins.get(key);
    if (bin3 === void 0) {
      bin3 = { index: [], extent: { data, x: (pi7 + (pj & 1) / 2) * dx + ox, y: pj * dy + oy } };
      bins.set(key, bin3);
    }
    bin3.index.push(i);
  }
  return bins.values();
}

// node_modules/@observablehq/plot/src/marks/hexgrid.js
var defaults19 = {
  ariaLabel: "hexgrid",
  fill: "none",
  stroke: "currentColor",
  strokeOpacity: 0.1
};
function hexgrid(options) {
  return new Hexgrid(options);
}
var Hexgrid = class extends Mark {
  constructor({ binWidth = 20, clip = true, ...options } = {}) {
    super(singleton, void 0, { clip, ...options }, defaults19);
    this.binWidth = number5(binWidth);
  }
  render(index2, scales, channels, dimensions, context) {
    const { binWidth } = this;
    const { marginTop, marginRight, marginBottom, marginLeft, width, height } = dimensions;
    const x06 = marginLeft - ox, x12 = width - marginRight - ox, y06 = marginTop - oy, y12 = height - marginBottom - oy, rx = binWidth / 2, ry = rx * sqrt4_3, hy = ry / 2, wx = rx * 2, wy = ry * 1.5, i0 = Math.floor(x06 / wx), i1 = Math.ceil(x12 / wx), j0 = Math.floor((y06 + hy) / wy), j1 = Math.ceil((y12 - hy) / wy) + 1, path2 = `m0,${round(-ry)}l${round(rx)},${round(hy)}v${round(ry)}l${round(-rx)},${round(hy)}`;
    let d = path2;
    for (let j = j0; j < j1; ++j) {
      for (let i = i0; i < i1; ++i) {
        d += `M${round(i * wx + (j & 1) * rx)},${round(j * wy)}${path2}`;
      }
    }
    return create2("svg:g", context).datum(0).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, {}, offset + ox, offset + oy).call((g) => g.append("path").call(applyDirectStyles, this).call(applyChannelStyles, this, channels).attr("d", d)).node();
  }
};
function round(x3) {
  return Math.round(x3 * 1e3) / 1e3;
}

// node_modules/@observablehq/plot/src/marks/image.js
var defaults20 = {
  ariaLabel: "image",
  fill: null,
  stroke: null
};
function isPath(string2) {
  return /^\.*\//.test(string2);
}
function isUrl(string2) {
  return /^(blob|data|file|http|https):/i.test(string2);
}
function maybePathChannel(value) {
  return typeof value === "string" && (isPath(value) || isUrl(value)) ? [void 0, value] : [value, void 0];
}
var Image2 = class extends Mark {
  constructor(data, options = {}) {
    let { x: x3, y: y3, r, width, height, rotate, src, preserveAspectRatio, crossOrigin, frameAnchor, imageRendering } = options;
    if (r == null) r = void 0;
    if (r === void 0 && width === void 0 && height === void 0) width = height = 16;
    else if (width === void 0 && height !== void 0) width = height;
    else if (height === void 0 && width !== void 0) height = width;
    const [vs, cs] = maybePathChannel(src);
    const [vr, cr] = maybeNumberChannel(r);
    const [vw, cw] = maybeNumberChannel(width, cr !== void 0 ? cr * 2 : void 0);
    const [vh, ch] = maybeNumberChannel(height, cr !== void 0 ? cr * 2 : void 0);
    const [va, ca3] = maybeNumberChannel(rotate, 0);
    super(
      data,
      {
        x: { value: x3, scale: "x", optional: true },
        y: { value: y3, scale: "y", optional: true },
        r: { value: vr, scale: "r", filter: positive, optional: true },
        width: { value: vw, filter: positive, optional: true },
        height: { value: vh, filter: positive, optional: true },
        rotate: { value: va, optional: true },
        src: { value: vs, optional: true }
      },
      withDefaultSort(options),
      defaults20
    );
    this.src = cs;
    this.width = cw;
    this.rotate = ca3;
    this.height = ch;
    this.r = cr;
    this.preserveAspectRatio = impliedString(preserveAspectRatio, "xMidYMid");
    this.crossOrigin = string(crossOrigin);
    this.frameAnchor = maybeFrameAnchor(frameAnchor);
    this.imageRendering = impliedString(imageRendering, "auto");
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: x3, y: y3 } = scales;
    const { x: X3, y: Y3, width: W, height: H, r: R, rotate: A5, src: S } = channels;
    const { r, width, height, rotate } = this;
    const [cx, cy] = applyFrameAnchor(this, dimensions);
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, { x: X3 && x3, y: Y3 && y3 }).call(
      (g) => g.selectAll().data(index2).enter().append("image").call(applyDirectStyles, this).attr("x", position2(X3, W, R, cx, width, r)).attr("y", position2(Y3, H, R, cy, height, r)).attr("width", W ? (i) => W[i] : width !== void 0 ? width : R ? (i) => R[i] * 2 : r * 2).attr("height", H ? (i) => H[i] : height !== void 0 ? height : R ? (i) => R[i] * 2 : r * 2).attr("transform", A5 ? (i) => `rotate(${A5[i]})` : rotate ? `rotate(${rotate})` : null).attr("transform-origin", A5 || rotate ? template`${X3 ? (i) => X3[i] : cx}px ${Y3 ? (i) => Y3[i] : cy}px` : null).call(applyAttr, "href", S ? (i) => S[i] : this.src).call(applyAttr, "preserveAspectRatio", this.preserveAspectRatio).call(applyAttr, "crossorigin", this.crossOrigin).call(applyAttr, "image-rendering", this.imageRendering).call(applyAttr, "clip-path", R ? (i) => `circle(${R[i]}px)` : r !== void 0 ? `circle(${r}px)` : null).call(applyChannelStyles, this, channels)
    ).node();
  }
};
function position2(X3, W, R, x3, w, r) {
  return W && X3 ? (i) => X3[i] - W[i] / 2 : W ? (i) => x3 - W[i] / 2 : X3 && w !== void 0 ? (i) => X3[i] - w / 2 : w !== void 0 ? x3 - w / 2 : R && X3 ? (i) => X3[i] - R[i] : R ? (i) => x3 - R[i] : X3 ? (i) => X3[i] - r : x3 - r;
}
function image(data, { x: x3, y: y3, ...options } = {}) {
  if (options.frameAnchor === void 0) [x3, y3] = maybeTuple(x3, y3);
  return new Image2(data, { ...options, x: x3, y: y3 });
}

// node_modules/@observablehq/plot/src/stats.js
function ibetainv(p, a2, b) {
  var EPS = 1e-8;
  var a1 = a2 - 1;
  var b12 = b - 1;
  var j = 0;
  var lna, lnb, pp, t, u4, err, x3, al, h, w, afac;
  if (p <= 0) return 0;
  if (p >= 1) return 1;
  if (a2 >= 1 && b >= 1) {
    pp = p < 0.5 ? p : 1 - p;
    t = Math.sqrt(-2 * Math.log(pp));
    x3 = (2.30753 + t * 0.27061) / (1 + t * (0.99229 + t * 0.04481)) - t;
    if (p < 0.5) x3 = -x3;
    al = (x3 * x3 - 3) / 6;
    h = 2 / (1 / (2 * a2 - 1) + 1 / (2 * b - 1));
    w = x3 * Math.sqrt(al + h) / h - (1 / (2 * b - 1) - 1 / (2 * a2 - 1)) * (al + 5 / 6 - 2 / (3 * h));
    x3 = a2 / (a2 + b * Math.exp(2 * w));
  } else {
    lna = Math.log(a2 / (a2 + b));
    lnb = Math.log(b / (a2 + b));
    t = Math.exp(a2 * lna) / a2;
    u4 = Math.exp(b * lnb) / b;
    w = t + u4;
    if (p < t / w) x3 = Math.pow(a2 * w * p, 1 / a2);
    else x3 = 1 - Math.pow(b * w * (1 - p), 1 / b);
  }
  afac = -gammaln(a2) - gammaln(b) + gammaln(a2 + b);
  for (; j < 10; j++) {
    if (x3 === 0 || x3 === 1) return x3;
    err = ibeta(x3, a2, b) - p;
    t = Math.exp(a1 * Math.log(x3) + b12 * Math.log(1 - x3) + afac);
    u4 = err / t;
    x3 -= t = u4 / (1 - 0.5 * Math.min(1, u4 * (a1 / x3 - b12 / (1 - x3))));
    if (x3 <= 0) x3 = 0.5 * (x3 + t);
    if (x3 >= 1) x3 = 0.5 * (x3 + t + 1);
    if (Math.abs(t) < EPS * x3 && j > 0) break;
  }
  return x3;
}
function ibeta(x3, a2, b) {
  var bt = x3 === 0 || x3 === 1 ? 0 : Math.exp(gammaln(a2 + b) - gammaln(a2) - gammaln(b) + a2 * Math.log(x3) + b * Math.log(1 - x3));
  if (x3 < 0 || x3 > 1) return false;
  if (x3 < (a2 + 1) / (a2 + b + 2))
    return bt * betacf(x3, a2, b) / a2;
  return 1 - bt * betacf(1 - x3, b, a2) / b;
}
function betacf(x3, a2, b) {
  var fpmin = 1e-30;
  var m = 1;
  var qab = a2 + b;
  var qap = a2 + 1;
  var qam = a2 - 1;
  var c4 = 1;
  var d = 1 - qab * x3 / qap;
  var m2, aa2, del, h;
  if (Math.abs(d) < fpmin) d = fpmin;
  d = 1 / d;
  h = d;
  for (; m <= 100; m++) {
    m2 = 2 * m;
    aa2 = m * (b - m) * x3 / ((qam + m2) * (a2 + m2));
    d = 1 + aa2 * d;
    if (Math.abs(d) < fpmin) d = fpmin;
    c4 = 1 + aa2 / c4;
    if (Math.abs(c4) < fpmin) c4 = fpmin;
    d = 1 / d;
    h *= d * c4;
    aa2 = -(a2 + m) * (qab + m) * x3 / ((a2 + m2) * (qap + m2));
    d = 1 + aa2 * d;
    if (Math.abs(d) < fpmin) d = fpmin;
    c4 = 1 + aa2 / c4;
    if (Math.abs(c4) < fpmin) c4 = fpmin;
    d = 1 / d;
    del = d * c4;
    h *= del;
    if (Math.abs(del - 1) < 3e-7) break;
  }
  return h;
}
function gammaln(x3) {
  var j = 0;
  var cof = [
    76.18009172947146,
    -86.5053203294167,
    24.01409824083091,
    -1.231739572450155,
    0.001208650973866179,
    -5395239384953e-18
  ];
  var ser = 1.000000000190015;
  var xx, y3, tmp;
  tmp = (y3 = xx = x3) + 5.5;
  tmp -= (xx + 0.5) * Math.log(tmp);
  for (; j < 6; j++) ser += cof[j] / ++y3;
  return Math.log(2.506628274631 * ser / xx) - tmp;
}
function qt(p, dof) {
  var x3 = ibetainv(2 * Math.min(p, 1 - p), 0.5 * dof, 0.5);
  x3 = Math.sqrt(dof * (1 - x3) / x3);
  return p > 0.5 ? x3 : -x3;
}

// node_modules/@observablehq/plot/src/marks/linearRegression.js
var defaults21 = {
  ariaLabel: "linear-regression",
  fill: "currentColor",
  fillOpacity: 0.1,
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  strokeMiterlimit: 1
};
var LinearRegression = class extends Mark {
  constructor(data, options = {}) {
    const { x: x3, y: y3, z, ci = 0.95, precision = 4 } = options;
    super(
      data,
      {
        x: { value: x3, scale: "x" },
        y: { value: y3, scale: "y" },
        z: { value: maybeZ(options), optional: true }
      },
      options,
      defaults21
    );
    this.z = z;
    this.ci = +ci;
    this.precision = +precision;
    if (!(0 <= this.ci && this.ci < 1)) throw new Error(`invalid ci; not in [0, 1): ${ci}`);
    if (!(this.precision > 0)) throw new Error(`invalid precision: ${precision}`);
  }
  render(index2, scales, channels, dimensions, context) {
    const { x: X3, y: Y3, z: Z } = channels;
    const { ci } = this;
    return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(applyTransform, this, scales).call(
      (g) => g.selectAll().data(Z ? groupZ2(index2, Z, this.z) : [index2]).enter().call(
        (enter) => enter.append("path").attr("fill", "none").call(applyDirectStyles, this).call(applyGroupedChannelStyles, this, { ...channels, fill: null, fillOpacity: null }).attr("d", (I) => this._renderLine(I, X3, Y3)).call(
          ci && !isNone(this.fill) ? (path2) => path2.select(pathBefore).attr("stroke", "none").call(applyDirectStyles, this).call(applyGroupedChannelStyles, this, {
            ...channels,
            stroke: null,
            strokeOpacity: null,
            strokeWidth: null
          }).attr("d", (I) => this._renderBand(I, X3, Y3)) : () => {
          }
        )
      )
    ).node();
  }
};
function pathBefore() {
  return this.parentNode.insertBefore(this.ownerDocument.createElementNS(namespaces_default.svg, "path"), this);
}
var LinearRegressionX = class extends LinearRegression {
  constructor(data, options) {
    super(data, options);
  }
  _renderBand(I, X3, Y3) {
    const { ci, precision } = this;
    const [y12, y22] = extent(I, (i) => Y3[i]);
    const f = linearRegressionF(I, Y3, X3);
    const g = confidenceIntervalF(I, Y3, X3, (1 - ci) / 2, f);
    return area_default5().y((y3) => y3).x0((y3) => g(y3, -1)).x1((y3) => g(y3, 1))(range(y12, y22 - precision / 2, precision).concat(y22));
  }
  _renderLine(I, X3, Y3) {
    const [y12, y22] = extent(I, (i) => Y3[i]);
    const f = linearRegressionF(I, Y3, X3);
    return `M${f(y12)},${y12}L${f(y22)},${y22}`;
  }
};
var LinearRegressionY = class extends LinearRegression {
  constructor(data, options) {
    super(data, options);
  }
  _renderBand(I, X3, Y3) {
    const { ci, precision } = this;
    const [x12, x22] = extent(I, (i) => X3[i]);
    const f = linearRegressionF(I, X3, Y3);
    const g = confidenceIntervalF(I, X3, Y3, (1 - ci) / 2, f);
    return area_default5().x((x3) => x3).y0((x3) => g(x3, -1)).y1((x3) => g(x3, 1))(range(x12, x22 - precision / 2, precision).concat(x22));
  }
  _renderLine(I, X3, Y3) {
    const [x12, x22] = extent(I, (i) => X3[i]);
    const f = linearRegressionF(I, X3, Y3);
    return `M${x12},${f(x12)}L${x22},${f(x22)}`;
  }
};
function linearRegressionX(data, { y: y3 = indexOf, x: x3 = identity6, stroke, fill = isNoneish(stroke) ? "currentColor" : stroke, ...options } = {}) {
  return new LinearRegressionX(data, maybeDenseIntervalY({ ...options, x: x3, y: y3, fill, stroke }));
}
function linearRegressionY(data, { x: x3 = indexOf, y: y3 = identity6, stroke, fill = isNoneish(stroke) ? "currentColor" : stroke, ...options } = {}) {
  return new LinearRegressionY(data, maybeDenseIntervalX({ ...options, x: x3, y: y3, fill, stroke }));
}
function linearRegressionF(I, X3, Y3) {
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  for (const i of I) {
    const xi = X3[i];
    const yi = Y3[i];
    sumX += xi;
    sumY += yi;
    sumXY += xi * yi;
    sumX2 += xi * xi;
  }
  const n = I.length;
  const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
  const intercept = (sumY - slope * sumX) / n;
  return (x3) => slope * x3 + intercept;
}
function confidenceIntervalF(I, X3, Y3, p, f) {
  const mean2 = sum(I, (i) => X3[i]) / I.length;
  let a2 = 0, b = 0;
  for (const i of I) {
    a2 += (X3[i] - mean2) ** 2;
    b += (Y3[i] - f(X3[i])) ** 2;
  }
  const sy = Math.sqrt(b / (I.length - 2));
  const t = qt(p, I.length - 2);
  return (x3, k2) => {
    const Y4 = f(x3);
    const se = sy * Math.sqrt(1 / I.length + (x3 - mean2) ** 2 / a2);
    return Y4 + k2 * t * se;
  };
}

// node_modules/@observablehq/plot/src/transforms/tree.js
function treeNode({
  path: path2 = identity6,
  // the delimited path
  delimiter,
  // how the path is separated
  frameAnchor,
  treeLayout = tree_default,
  treeSort,
  treeSeparation,
  treeAnchor,
  treeFilter,
  ...options
} = {}) {
  treeAnchor = maybeTreeAnchor(treeAnchor);
  treeSort = maybeTreeSort(treeSort);
  if (treeFilter != null) treeFilter = maybeNodeValue(treeFilter);
  if (frameAnchor === void 0) frameAnchor = treeAnchor.frameAnchor;
  const normalize4 = normalizer(delimiter);
  const outputs = treeOutputs(options, maybeNodeValue);
  const [X3, setX] = column();
  const [Y3, setY] = column();
  return {
    x: X3,
    y: Y3,
    frameAnchor,
    ...basic(options, (data, facets) => {
      const P = normalize4(valueof(data, path2));
      const X4 = setX([]);
      const Y4 = setY([]);
      let treeIndex = -1;
      const treeData = [];
      const treeFacets = [];
      const rootof = stratify_default().path((i) => P[i]);
      const setData = isArray(data) ? (node) => node.data = data[node.data] : (node) => node.data = data.get(node.data);
      const layout = treeLayout();
      if (layout.nodeSize) layout.nodeSize([1, 1]);
      if (layout.separation && treeSeparation !== void 0) layout.separation(treeSeparation ?? one2);
      for (const o of outputs) o[output_values] = o[output_setValues]([]);
      for (const facet of facets) {
        const treeFacet = [];
        const root2 = rootof(facet.filter((i) => P[i] != null)).each(setData);
        if (treeSort != null) root2.sort(treeSort);
        layout(root2);
        for (const node of root2.descendants()) {
          if (treeFilter != null && !treeFilter(node)) continue;
          treeFacet.push(++treeIndex);
          treeData[treeIndex] = node.data;
          treeAnchor.position(node, treeIndex, X4, Y4);
          for (const o of outputs) o[output_values][treeIndex] = o[output_evaluate](node);
        }
        treeFacets.push(treeFacet);
      }
      return { data: treeData, facets: treeFacets };
    }),
    ...Object.fromEntries(outputs)
  };
}
function treeLink({
  path: path2 = identity6,
  // the delimited path
  delimiter,
  // how the path is separated
  curve = "bump-x",
  stroke = "#555",
  strokeWidth = 1.5,
  strokeOpacity = 0.5,
  treeLayout = tree_default,
  treeSort,
  treeSeparation,
  treeAnchor,
  treeFilter,
  ...options
} = {}) {
  treeAnchor = maybeTreeAnchor(treeAnchor);
  treeSort = maybeTreeSort(treeSort);
  if (treeFilter != null) treeFilter = maybeLinkValue(treeFilter);
  options = { curve, stroke, strokeWidth, strokeOpacity, ...options };
  const normalize4 = normalizer(delimiter);
  const outputs = treeOutputs(options, maybeLinkValue);
  const [X13, setX1] = column();
  const [X23, setX2] = column();
  const [Y13, setY1] = column();
  const [Y23, setY2] = column();
  return {
    x1: X13,
    x2: X23,
    y1: Y13,
    y2: Y23,
    ...basic(options, (data, facets) => {
      const P = normalize4(valueof(data, path2));
      const X14 = setX1([]);
      const X24 = setX2([]);
      const Y14 = setY1([]);
      const Y24 = setY2([]);
      let treeIndex = -1;
      const treeData = [];
      const treeFacets = [];
      const rootof = stratify_default().path((i) => P[i]);
      const layout = treeLayout();
      if (layout.nodeSize) layout.nodeSize([1, 1]);
      if (layout.separation && treeSeparation !== void 0) layout.separation(treeSeparation ?? one2);
      for (const o of outputs) o[output_values] = o[output_setValues]([]);
      for (const facet of facets) {
        const treeFacet = [];
        const root2 = rootof(facet.filter((i) => P[i] != null)).each((node) => node.data = data[node.data]);
        if (treeSort != null) root2.sort(treeSort);
        layout(root2);
        for (const { source, target } of root2.links()) {
          if (treeFilter != null && !treeFilter(target, source)) continue;
          treeFacet.push(++treeIndex);
          treeData[treeIndex] = target.data;
          treeAnchor.position(source, treeIndex, X14, Y14);
          treeAnchor.position(target, treeIndex, X24, Y24);
          for (const o of outputs) o[output_values][treeIndex] = o[output_evaluate](target, source);
        }
        treeFacets.push(treeFacet);
      }
      return { data: treeData, facets: treeFacets };
    }),
    ...Object.fromEntries(outputs)
  };
}
function maybeTreeAnchor(anchor = "left") {
  switch (`${anchor}`.trim().toLowerCase()) {
    case "left":
      return treeAnchorLeft;
    case "right":
      return treeAnchorRight;
  }
  throw new Error(`invalid tree anchor: ${anchor}`);
}
var treeAnchorLeft = {
  frameAnchor: "left",
  dx: 6,
  position({ x: x3, y: y3 }, i, X3, Y3) {
    X3[i] = y3;
    Y3[i] = -x3;
  }
};
var treeAnchorRight = {
  frameAnchor: "right",
  dx: -6,
  position({ x: x3, y: y3 }, i, X3, Y3) {
    X3[i] = -y3;
    Y3[i] = -x3;
  }
};
function maybeTreeSort(sort3) {
  return sort3 == null || typeof sort3 === "function" ? sort3 : `${sort3}`.trim().toLowerCase().startsWith("node:") ? nodeSort(maybeNodeValue(sort3)) : nodeSort(nodeData(sort3));
}
function nodeSort(value) {
  return (a2, b) => ascendingDefined2(value(a2), value(b));
}
function nodeData(field2) {
  return (node) => {
    var _a;
    return (_a = node.data) == null ? void 0 : _a[field2];
  };
}
function normalizer(delimiter = "/") {
  delimiter = `${delimiter}`;
  if (delimiter === "/") return (P) => P;
  if (delimiter.length !== 1) throw new Error("delimiter must be exactly one character");
  const delimiterCode = delimiter.charCodeAt(0);
  return (P) => P.map((p) => slashDelimiter(p, delimiterCode));
}
var CODE_BACKSLASH = 92;
var CODE_SLASH = 47;
function slashDelimiter(input, delimiterCode) {
  if (delimiterCode === CODE_BACKSLASH) throw new Error("delimiter cannot be backslash");
  let afterBackslash = false;
  for (let i = 0, n = input.length; i < n; ++i) {
    switch (input.charCodeAt(i)) {
      case CODE_BACKSLASH:
        if (!afterBackslash) {
          afterBackslash = true;
          continue;
        }
        break;
      case delimiterCode:
        if (afterBackslash) {
          input = input.slice(0, i - 1) + input.slice(i), --i, --n;
        } else {
          input = input.slice(0, i) + "/" + input.slice(i + 1);
        }
        break;
      case CODE_SLASH:
        if (afterBackslash) {
          input = input.slice(0, i) + "\\\\" + input.slice(i), i += 2, n += 2;
        } else {
          input = input.slice(0, i) + "\\" + input.slice(i), ++i, ++n;
        }
        break;
    }
    afterBackslash = false;
  }
  return input;
}
function slashUnescape(input) {
  let afterBackslash = false;
  for (let i = 0, n = input.length; i < n; ++i) {
    switch (input.charCodeAt(i)) {
      case CODE_BACKSLASH:
        if (!afterBackslash) {
          afterBackslash = true;
          continue;
        }
      // eslint-disable-next-line no-fallthrough
      case CODE_SLASH:
        if (afterBackslash) {
          input = input.slice(0, i - 1) + input.slice(i), --i, --n;
        }
        break;
    }
    afterBackslash = false;
  }
  return input;
}
function isNodeValue(option) {
  return isObject(option) && typeof option.node === "function";
}
function isLinkValue(option) {
  return isObject(option) && typeof option.link === "function";
}
function maybeNodeValue(value) {
  if (isNodeValue(value)) return value.node;
  value = `${value}`.trim().toLowerCase();
  if (!value.startsWith("node:")) return;
  switch (value) {
    case "node:name":
      return nodeName;
    case "node:path":
      return nodePath;
    case "node:internal":
      return nodeInternal;
    case "node:external":
      return nodeExternal;
    case "node:depth":
      return nodeDepth;
    case "node:height":
      return nodeHeight;
  }
  throw new Error(`invalid node value: ${value}`);
}
function maybeLinkValue(value) {
  if (isNodeValue(value)) return value.node;
  if (isLinkValue(value)) return value.link;
  value = `${value}`.trim().toLowerCase();
  if (!value.startsWith("node:") && !value.startsWith("parent:")) return;
  switch (value) {
    case "parent:name":
      return parentValue(nodeName);
    case "parent:path":
      return parentValue(nodePath);
    case "parent:depth":
      return parentValue(nodeDepth);
    case "parent:height":
      return parentValue(nodeHeight);
    case "node:name":
      return nodeName;
    case "node:path":
      return nodePath;
    case "node:internal":
      return nodeInternal;
    case "node:external":
      return nodeExternal;
    case "node:depth":
      return nodeDepth;
    case "node:height":
      return nodeHeight;
  }
  throw new Error(`invalid link value: ${value}`);
}
function nodePath(node) {
  return node.id;
}
function nodeName(node) {
  return nameof(node.id);
}
function nodeDepth(node) {
  return node.depth;
}
function nodeHeight(node) {
  return node.height;
}
function nodeInternal(node) {
  return !!node.children;
}
function nodeExternal(node) {
  return !node.children;
}
function parentValue(evaluate) {
  return (child, parent) => parent == null ? void 0 : evaluate(parent);
}
function nameof(path2) {
  let i = path2.length;
  while (--i > 0) if (slash2(path2, i)) break;
  return slashUnescape(path2.slice(i + 1));
}
function slash2(path2, i) {
  if (path2[i] === "/") {
    let k2 = 0;
    while (i > 0 && path2[--i] === "\\") ++k2;
    if ((k2 & 1) === 0) return true;
  }
  return false;
}
var output_setValues = 2;
var output_evaluate = 3;
var output_values = 4;
function treeOutputs(options, maybeTreeValue) {
  const outputs = [];
  for (const name in options) {
    const value = options[name];
    const treeValue = maybeTreeValue(value);
    if (treeValue !== void 0) {
      outputs.push([name, ...column(value), treeValue]);
    }
  }
  return outputs;
}

// node_modules/@observablehq/plot/src/marks/tree.js
function tree(data, {
  fill,
  stroke,
  strokeWidth,
  strokeOpacity,
  strokeLinejoin,
  strokeLinecap,
  strokeMiterlimit,
  strokeDasharray,
  strokeDashoffset,
  marker,
  markerStart = marker,
  markerEnd = marker,
  dot: dotDot = isNoneish(markerStart) && isNoneish(markerEnd),
  text: textText = "node:name",
  textStroke = "var(--plot-background)",
  title = "node:path",
  dx,
  dy,
  textAnchor,
  treeLayout = tree_default,
  textLayout = treeLayout === tree_default || treeLayout === cluster_default ? "mirrored" : "normal",
  tip: tip2,
  ...options
} = {}) {
  if (dx === void 0) dx = maybeTreeAnchor(options.treeAnchor).dx;
  if (textAnchor !== void 0) throw new Error("textAnchor is not a configurable tree option");
  textLayout = keyword(textLayout, "textLayout", ["mirrored", "normal"]);
  function treeText(textOptions2) {
    return text(
      data,
      treeNode({
        treeLayout,
        text: textText,
        fill: fill === void 0 ? "currentColor" : fill,
        stroke: textStroke,
        dx,
        dy,
        title,
        ...textOptions2,
        ...options
      })
    );
  }
  return marks(
    link3(
      data,
      treeLink({
        treeLayout,
        markerStart,
        markerEnd,
        stroke: stroke !== void 0 ? stroke : fill === void 0 ? "node:internal" : fill,
        strokeWidth,
        strokeOpacity,
        strokeLinejoin,
        strokeLinecap,
        strokeMiterlimit,
        strokeDasharray,
        strokeDashoffset,
        ...options
      })
    ),
    dotDot ? dot(data, treeNode({ treeLayout, fill: fill === void 0 ? "node:internal" : fill, title, tip: tip2, ...options })) : null,
    textText != null ? textLayout === "mirrored" ? [
      treeText({ textAnchor: "start", treeFilter: "node:external" }),
      treeText({ textAnchor: "end", treeFilter: "node:internal", dx: -dx })
    ] : treeText() : null
  );
}
function cluster(data, options) {
  return tree(data, { ...options, treeLayout: cluster_default });
}

// node_modules/@observablehq/plot/src/marks/waffle.js
var waffleDefaults = {
  ariaLabel: "waffle"
};
var WaffleX = class extends BarX {
  constructor(data, { unit: unit3 = 1, gap = 1, round: round2, multiple, ...options } = {}) {
    super(data, wafflePolygon("x", options), waffleDefaults);
    this.unit = Math.max(0, unit3);
    this.gap = +gap;
    this.round = maybeRound2(round2);
    this.multiple = maybeMultiple(multiple);
  }
};
var WaffleY = class extends BarY {
  constructor(data, { unit: unit3 = 1, gap = 1, round: round2, multiple, ...options } = {}) {
    super(data, wafflePolygon("y", options), waffleDefaults);
    this.unit = Math.max(0, unit3);
    this.gap = +gap;
    this.round = maybeRound2(round2);
    this.multiple = maybeMultiple(multiple);
  }
};
function wafflePolygon(y3, options) {
  const x3 = y3 === "y" ? "x" : "y";
  const y12 = `${y3}1`;
  const y22 = `${y3}2`;
  return initializer(waffleRender(options), function(data, facets, channels, scales, dimensions) {
    const { round: round2, unit: unit3 } = this;
    const Y13 = channels[y12].value;
    const Y23 = channels[y22].value;
    const xy = valueObject({ ...x3 in channels && { [x3]: channels[x3] }, [y12]: channels[y12], [y22]: channels[y22] }, scales);
    const barwidth = this[y3 === "y" ? "_width" : "_height"](scales, xy, dimensions);
    const barx = this[y3 === "y" ? "_x" : "_y"](scales, xy, dimensions);
    const scale3 = unit3 * scaleof(scales.scales[y3]);
    const { multiple = Math.max(1, Math.floor(Math.sqrt(barwidth / scale3))) } = this;
    const cx = Math.min(barwidth / multiple, scale3 * multiple);
    const cy = scale3 * multiple;
    const tx = (barwidth - multiple * cx) / 2;
    const x06 = typeof barx === "function" ? (i) => barx(i) + tx : barx + tx;
    const y06 = scales[y3](0);
    const transform2 = y3 === "y" ? ([x4, y4]) => [x4 * cx, -y4 * cy] : ([x4, y4]) => [y4 * cy, x4 * cx];
    const mx = typeof x06 === "function" ? (i) => x06(i) - barwidth / 2 : () => x06;
    const [ix, iy] = y3 === "y" ? [0, 1] : [1, 0];
    const n = Y23.length;
    const P = new Array(n);
    const X3 = new Float64Array(n);
    const Y3 = new Float64Array(n);
    for (let i = 0; i < n; ++i) {
      P[i] = wafflePoints(round2(Y13[i] / unit3), round2(Y23[i] / unit3), multiple).map(transform2);
      const c4 = P[i].pop();
      X3[i] = c4[ix] + mx(i);
      Y3[i] = c4[iy] + y06;
    }
    return {
      channels: {
        polygon: { value: P, source: null, filter: null },
        [`c${x3}`]: { value: [cx, x06], source: null, filter: null },
        [`c${y3}`]: { value: [cy, y06], source: null, filter: null },
        [x3]: { value: X3, scale: null, source: null },
        [y12]: { value: Y3, scale: null, source: channels[y12] },
        [y22]: { value: Y3, scale: null, source: channels[y22] }
      }
    };
  });
}
function waffleRender({ render, ...options }) {
  return {
    ...options,
    render: composeRender(render, function(index2, scales, values2, dimensions, context) {
      const { gap, rx, ry } = this;
      const { channels, ariaLabel, href, title, ...visualValues } = values2;
      const { document: document2 } = context;
      const polygon = channels.polygon.value;
      const [cx, x06] = channels.cx.value;
      const [cy, y06] = channels.cy.value;
      const patternId = getPatternId();
      const basePattern = document2.createElementNS(namespaces_default.svg, "pattern");
      basePattern.setAttribute("width", cx);
      basePattern.setAttribute("height", cy);
      basePattern.setAttribute("patternUnits", "userSpaceOnUse");
      const basePatternRect = basePattern.appendChild(document2.createElementNS(namespaces_default.svg, "rect"));
      basePatternRect.setAttribute("x", gap / 2);
      basePatternRect.setAttribute("y", gap / 2);
      basePatternRect.setAttribute("width", cx - gap);
      basePatternRect.setAttribute("height", cy - gap);
      if (rx != null) basePatternRect.setAttribute("rx", rx);
      if (ry != null) basePatternRect.setAttribute("ry", ry);
      return create2("svg:g", context).call(applyIndirectStyles, this, dimensions, context).call(this._transform, this, scales).call(
        (g) => g.selectAll().data(index2).enter().append(() => basePattern.cloneNode(true)).attr("id", (i) => `${patternId}-${i}`).select("rect").call(applyDirectStyles, this).call(applyChannelStyles, this, visualValues)
      ).call(
        (g) => g.selectAll().data(index2).enter().append("path").attr("transform", template`translate(${x06},${y06})`).attr("d", (i) => `M${polygon[i].join("L")}Z`).attr("fill", (i) => `url(#${patternId}-${i})`).attr("stroke", this.stroke == null ? null : "none").call(applyChannelStyles, this, { ariaLabel, href, title })
      ).node();
    })
  };
}
function wafflePoints(i1, i2, columns) {
  if (i2 < i1) return wafflePoints(i2, i1, columns);
  if (i1 < 0) return wafflePointsOffset(i1, i2, columns, Math.ceil(-Math.min(i1, i2) / columns));
  const x1f = Math.floor(i1 % columns);
  const x1c = Math.ceil(i1 % columns);
  const x2f = Math.floor(i2 % columns);
  const x2c = Math.ceil(i2 % columns);
  const y1f = Math.floor(i1 / columns);
  const y1c = Math.ceil(i1 / columns);
  const y2f = Math.floor(i2 / columns);
  const y2c = Math.ceil(i2 / columns);
  const points = [];
  if (y2c > y1c) points.push([0, y1c]);
  points.push([x1f, y1c], [x1f, y1f + i1 % 1], [x1c, y1f + i1 % 1]);
  if (!(i1 % columns > columns - 1)) {
    points.push([x1c, y1f]);
    if (y2f > y1f) points.push([columns, y1f]);
  }
  if (y2f > y1f) points.push([columns, y2f]);
  points.push([x2c, y2f], [x2c, y2f + i2 % 1], [x2f, y2f + i2 % 1]);
  if (!(i2 % columns < 1)) {
    points.push([x2f, y2c]);
    if (y2c > y1c) points.push([0, y2c]);
  }
  points.push(waffleCentroid(i1, i2, columns));
  return points;
}
function wafflePointsOffset(i1, i2, columns, k2) {
  return wafflePoints(i1 + k2 * columns, i2 + k2 * columns, columns).map(([x3, y3]) => [x3, y3 - k2]);
}
function waffleCentroid(i1, i2, columns) {
  const r = Math.floor(i2 / columns) - Math.floor(i1 / columns);
  return r === 0 ? (
    // Single row
    waffleRowCentroid(i1, i2, columns)
  ) : r === 1 ? (
    // Two incomplete rows; use the midpoint of their overlap if any, otherwise the larger row
    Math.floor(i2 % columns) > Math.ceil(i1 % columns) ? [(Math.floor(i2 % columns) + Math.ceil(i1 % columns)) / 2, Math.floor(i2 / columns)] : i2 % columns > columns - i1 % columns ? waffleRowCentroid(i2 - i2 % columns, i2, columns) : waffleRowCentroid(i1, columns * Math.ceil(i1 / columns), columns)
  ) : (
    // At least one full row; take the midpoint of all the rows that include the middle
    [columns / 2, (Math.round(i1 / columns) + Math.round(i2 / columns)) / 2]
  );
}
function waffleRowCentroid(i1, i2, columns) {
  const c4 = Math.floor(i2) - Math.floor(i1);
  return c4 === 0 ? (
    // Single cell
    [Math.floor(i1 % columns) + 0.5, Math.floor(i1 / columns) + (i1 + i2) / 2 % 1]
  ) : c4 === 1 ? (
    // Two incomplete cells; use the overlap if large enough, otherwise use the largest
    i2 % 1 - i1 % 1 > 0.5 ? [Math.ceil(i1 % columns), Math.floor(i2 / columns) + (i1 % 1 + i2 % 1) / 2] : i2 % 1 > 1 - i1 % 1 ? [Math.floor(i2 % columns) + 0.5, Math.floor(i2 / columns) + i2 % 1 / 2] : [Math.floor(i1 % columns) + 0.5, Math.floor(i1 / columns) + (1 + i1 % 1) / 2]
  ) : (
    // At least one full cell; take the midpoint
    [
      Math.ceil(i1 % columns) + Math.ceil(Math.floor(i2) - Math.ceil(i1)) / 2,
      Math.floor(i1 / columns) + (i2 >= 1 + i1 ? 0.5 : (i1 + i2) / 2 % 1)
    ]
  );
}
function maybeRound2(round2) {
  if (round2 === void 0 || round2 === false) return Number;
  if (round2 === true) return Math.round;
  if (typeof round2 !== "function") throw new Error(`invalid round: ${round2}`);
  return round2;
}
function maybeMultiple(multiple) {
  return multiple === void 0 ? void 0 : Math.max(1, Math.floor(multiple));
}
function scaleof({ domain, range: range3 }) {
  return spread(range3) / spread(domain);
}
function spread(domain) {
  const [min4, max5] = extent(domain);
  return max5 - min4;
}
function waffleX(data, { tip: tip2, ...options } = {}) {
  if (!hasXY(options)) options = { ...options, y: indexOf, x2: identity6 };
  return new WaffleX(data, { tip: waffleTip(tip2), ...maybeStackX(maybeIntervalX(maybeIdentityX(options))) });
}
function waffleY(data, { tip: tip2, ...options } = {}) {
  if (!hasXY(options)) options = { ...options, x: indexOf, y2: identity6 };
  return new WaffleY(data, { tip: waffleTip(tip2), ...maybeStackY(maybeIntervalY(maybeIdentityY(options))) });
}
function waffleTip(tip2) {
  return tip2 === true ? { maxRadius: Infinity } : isObject(tip2) && tip2.maxRadius === void 0 ? { ...tip2, maxRadius: Infinity } : void 0;
}

// node_modules/@observablehq/plot/src/transforms/dodge.js
var import_interval_tree_1d = __toESM(require_interval_tree(), 1);
var anchorXLeft = ({ marginLeft }) => [1, marginLeft];
var anchorXRight = ({ width, marginRight }) => [-1, width - marginRight];
var anchorXMiddle = ({ width, marginLeft, marginRight }) => [0, (marginLeft + width - marginRight) / 2];
var anchorYTop = ({ marginTop }) => [1, marginTop];
var anchorYBottom = ({ height, marginBottom }) => [-1, height - marginBottom];
var anchorYMiddle = ({ height, marginTop, marginBottom }) => [0, (marginTop + height - marginBottom) / 2];
function maybeAnchor4(anchor) {
  return typeof anchor === "string" ? { anchor } : anchor;
}
function dodgeX(dodgeOptions = {}, options = {}) {
  if (arguments.length === 1) [dodgeOptions, options] = mergeOptions3(dodgeOptions);
  let { anchor = "left", padding = 1, r = options.r } = maybeAnchor4(dodgeOptions);
  switch (`${anchor}`.toLowerCase()) {
    case "left":
      anchor = anchorXLeft;
      break;
    case "right":
      anchor = anchorXRight;
      break;
    case "middle":
      anchor = anchorXMiddle;
      break;
    default:
      throw new Error(`unknown dodge anchor: ${anchor}`);
  }
  return dodge("x", "y", anchor, number5(padding), r, options);
}
function dodgeY(dodgeOptions = {}, options = {}) {
  if (arguments.length === 1) [dodgeOptions, options] = mergeOptions3(dodgeOptions);
  let { anchor = "bottom", padding = 1, r = options.r } = maybeAnchor4(dodgeOptions);
  switch (`${anchor}`.toLowerCase()) {
    case "top":
      anchor = anchorYTop;
      break;
    case "bottom":
      anchor = anchorYBottom;
      break;
    case "middle":
      anchor = anchorYMiddle;
      break;
    default:
      throw new Error(`unknown dodge anchor: ${anchor}`);
  }
  return dodge("y", "x", anchor, number5(padding), r, options);
}
function mergeOptions3(options) {
  const { anchor, padding, ...rest } = options;
  const { r } = rest;
  return [{ anchor, padding, r }, rest];
}
function dodge(y3, x3, anchor, padding, r, options) {
  if (r != null && typeof r !== "number") {
    let { channels, sort: sort3, reverse: reverse3 } = options;
    channels = maybeNamed(channels);
    if ((channels == null ? void 0 : channels.r) === void 0) options = { ...options, channels: { ...channels, r: { value: r, scale: "r" } } };
    if (sort3 === void 0 && reverse3 === void 0) options.sort = { channel: "-r" };
  }
  return initializer(options, function(data, facets, channels, scales, dimensions, context) {
    let { [x3]: X3, r: R } = channels;
    if (!channels[x3]) throw new Error(`missing channel: ${x3}`);
    ({ [x3]: X3 } = applyPosition(channels, scales, context));
    const cr = R ? void 0 : r !== void 0 ? number5(r) : this.r !== void 0 ? this.r : 3;
    if (R) R = valueof(R.value, scales[R.scale] || identity6, Float64Array);
    let [ky2, ty] = anchor(dimensions);
    const compare = ky2 ? compareAscending : compareSymmetric;
    const Y3 = new Float64Array(X3.length);
    const radius2 = R ? (i) => R[i] : () => cr;
    for (let I of facets) {
      const tree2 = (0, import_interval_tree_1d.default)();
      I = I.filter(R ? (i) => finite2(X3[i]) && positive(R[i]) : (i) => finite2(X3[i]));
      const intervals = new Float64Array(2 * I.length + 2);
      for (const i of I) {
        const ri = radius2(i);
        const y06 = ky2 ? ri + padding : 0;
        const l = X3[i] - ri;
        const h = X3[i] + ri;
        let k2 = 2;
        tree2.queryInterval(l - padding, h + padding, ([, , j]) => {
          const yj = Y3[j] - y06;
          const dx = X3[i] - X3[j];
          const dr = padding + (R ? R[i] + R[j] : 2 * cr);
          const dy = Math.sqrt(dr * dr - dx * dx);
          intervals[k2++] = yj - dy;
          intervals[k2++] = yj + dy;
        });
        let candidates = intervals.slice(0, k2);
        if (ky2) candidates = candidates.filter((y4) => y4 >= 0);
        out: for (const y4 of candidates.sort(compare)) {
          for (let j = 0; j < k2; j += 2) {
            if (intervals[j] + 1e-6 < y4 && y4 < intervals[j + 1] - 1e-6) {
              continue out;
            }
          }
          Y3[i] = y4 + y06;
          break;
        }
        tree2.insert([l, h, i]);
      }
    }
    if (!ky2) ky2 = 1;
    for (const I of facets) {
      for (const i of I) {
        Y3[i] = Y3[i] * ky2 + ty;
      }
    }
    return {
      data,
      facets,
      channels: {
        [y3]: { value: Y3, source: null },
        // don’t show in tooltip
        [x3]: { value: X3, source: channels[x3] },
        ...R && { r: { value: R, source: channels.r } }
      }
    };
  });
}
function compareSymmetric(a2, b) {
  return Math.abs(a2) - Math.abs(b);
}
function compareAscending(a2, b) {
  return a2 - b;
}

// node_modules/@observablehq/plot/src/transforms/normalize.js
function normalizeX(basis2, options) {
  if (arguments.length === 1) ({ basis: basis2, ...options } = basis2);
  return mapX(normalize3(basis2), options);
}
function normalizeY(basis2, options) {
  if (arguments.length === 1) ({ basis: basis2, ...options } = basis2);
  return mapY(normalize3(basis2), options);
}
function normalize3(basis2) {
  if (basis2 === void 0) return normalizeFirst;
  if (typeof basis2 === "function") return normalizeBasis(taker(basis2));
  if (/^p\d{2}$/i.test(basis2)) return normalizeAccessor(percentile(basis2));
  switch (`${basis2}`.toLowerCase()) {
    case "deviation":
      return normalizeDeviation;
    case "first":
      return normalizeFirst;
    case "last":
      return normalizeLast;
    case "max":
      return normalizeMax;
    case "mean":
      return normalizeMean;
    case "median":
      return normalizeMedian;
    case "min":
      return normalizeMin;
    case "sum":
      return normalizeSum;
    case "extent":
      return normalizeExtent;
  }
  throw new Error(`invalid basis: ${basis2}`);
}
function normalizeBasis(basis2) {
  return {
    mapIndex(I, S, T) {
      const b = +basis2(I, S);
      for (const i of I) {
        T[i] = S[i] === null ? NaN : S[i] / b;
      }
    }
  };
}
function normalizeAccessor(f) {
  return normalizeBasis((I, S) => f(I, (i) => S[i]));
}
var normalizeExtent = {
  mapIndex(I, S, T) {
    const [s1, s2] = extent(I, (i) => S[i]);
    const d = s2 - s1;
    for (const i of I) {
      T[i] = S[i] === null ? NaN : (S[i] - s1) / d;
    }
  }
};
var normalizeFirst = normalizeBasis((I, S) => {
  for (let i = 0; i < I.length; ++i) {
    const s2 = S[I[i]];
    if (defined(s2)) return s2;
  }
});
var normalizeLast = normalizeBasis((I, S) => {
  for (let i = I.length - 1; i >= 0; --i) {
    const s2 = S[I[i]];
    if (defined(s2)) return s2;
  }
});
var normalizeDeviation = {
  mapIndex(I, S, T) {
    const m = mean(I, (i) => S[i]);
    const d = deviation(I, (i) => S[i]);
    for (const i of I) {
      T[i] = S[i] === null ? NaN : d ? (S[i] - m) / d : 0;
    }
  }
};
var normalizeMax = normalizeAccessor(max);
var normalizeMean = normalizeAccessor(mean);
var normalizeMedian = normalizeAccessor(median);
var normalizeMin = normalizeAccessor(min);
var normalizeSum = normalizeAccessor(sum);

// node_modules/@observablehq/plot/src/transforms/shift.js
function shiftX(interval2, options) {
  return shiftK("x", interval2, options);
}
function shiftY(interval2, options) {
  return shiftK("y", interval2, options);
}
function shiftK(x3, interval2, options = {}) {
  let offset2;
  let k2 = 1;
  if (typeof interval2 === "number") {
    k2 = interval2;
    offset2 = (x4, k3) => +x4 + k3;
  } else {
    if (typeof interval2 === "string") {
      const sign3 = interval2.startsWith("-") ? -1 : 1;
      [interval2, k2] = parseTimeInterval(interval2.replace(/^[+-]/, ""));
      k2 *= sign3;
    }
    interval2 = maybeInterval(interval2);
    offset2 = (x4, k3) => interval2.offset(x4, k3);
  }
  const x12 = `${x3}1`;
  const x22 = `${x3}2`;
  const mapped = map5(
    {
      [x12]: (D3) => D3.map((d) => offset2(d, k2)),
      [x22]: (D3) => D3
    },
    options
  );
  const t = mapped[x22].transform;
  mapped[x22].transform = () => {
    const V = t();
    const [x06, x13] = extent(V);
    V.domain = k2 < 0 ? [x06, offset2(x13, k2)] : [offset2(x06, k2), x13];
    return V;
  };
  return mapped;
}

// node_modules/@observablehq/plot/src/transforms/select.js
function select(selector, options = {}) {
  if (typeof selector === "string") {
    switch (selector.toLowerCase()) {
      case "first":
        return selectFirst(options);
      case "last":
        return selectLast(options);
    }
  }
  if (typeof selector === "function") {
    return selectChannel(null, selector, options);
  }
  let key, value;
  for (key in selector) {
    if (value !== void 0) throw new Error("ambiguous selector; multiple inputs");
    value = maybeSelector(selector[key]);
  }
  if (value === void 0) throw new Error(`invalid selector: ${selector}`);
  return selectChannel(key, value, options);
}
function maybeSelector(selector) {
  if (typeof selector === "function") return selector;
  switch (`${selector}`.toLowerCase()) {
    case "min":
      return selectorMin;
    case "max":
      return selectorMax;
  }
  throw new Error(`unknown selector: ${selector}`);
}
function selectFirst(options) {
  return selectChannel(null, selectorFirst, options);
}
function selectLast(options) {
  return selectChannel(null, selectorLast, options);
}
function selectMinX(options) {
  return selectChannel("x", selectorMin, options);
}
function selectMinY(options) {
  return selectChannel("y", selectorMin, options);
}
function selectMaxX(options) {
  return selectChannel("x", selectorMax, options);
}
function selectMaxY(options) {
  return selectChannel("y", selectorMax, options);
}
function* selectorFirst(I) {
  yield I[0];
}
function* selectorLast(I) {
  yield I[I.length - 1];
}
function* selectorMin(I, X3) {
  yield least(I, (i) => X3[i]);
}
function* selectorMax(I, X3) {
  yield greatest(I, (i) => X3[i]);
}
function selectChannel(v2, selector, options) {
  if (v2 != null) {
    if (options[v2] == null) throw new Error(`missing channel: ${v2}`);
    v2 = options[v2];
  }
  const z = maybeZ(options);
  return basic(options, (data, facets) => {
    const Z = valueof(data, z);
    const V = valueof(data, v2);
    const selectFacets = [];
    for (const facet of facets) {
      const selectFacet = [];
      for (const I of Z ? group(facet, (i) => Z[i]).values() : [facet]) {
        for (const i of selector(I, V)) {
          selectFacet.push(i);
        }
      }
      selectFacets.push(selectFacet);
    }
    return { data, facets: selectFacets };
  });
}

// node_modules/@observablehq/plot/src/index.js
Mark.prototype.plot = function({ marks: marks2 = [], ...options } = {}) {
  return plot({ ...options, marks: [...marks2, this] });
};
export {
  Area,
  Arrow,
  BarX,
  BarY,
  Cell,
  Contour,
  Density,
  Dot,
  Frame,
  Geo,
  Hexgrid,
  Image2 as Image,
  Line,
  Link,
  Mark,
  Raster,
  Rect,
  RuleX,
  RuleY,
  Text,
  TickX,
  TickY,
  Tip,
  Vector,
  WaffleX,
  WaffleY,
  area,
  areaX,
  areaY,
  arrow,
  auto,
  autoSpec,
  axisFx,
  axisFy,
  axisX,
  axisY,
  barX,
  barY,
  bin2 as bin,
  binX,
  binY,
  bollinger,
  bollingerX,
  bollingerY,
  boxX,
  boxY,
  cell,
  cellX,
  cellY,
  centroid,
  circle,
  cluster,
  column,
  contour,
  crosshair,
  crosshairX,
  crosshairY,
  delaunayLink,
  delaunayMesh,
  density,
  differenceX,
  differenceY,
  dodgeX,
  dodgeY,
  dot,
  dotX,
  dotY,
  filter3 as filter,
  find2 as find,
  formatIsoDate,
  formatMonth,
  formatNumber,
  formatWeekday,
  frame2 as frame,
  geo,
  geoCentroid,
  graticule2 as graticule,
  gridFx,
  gridFy,
  gridX,
  gridY,
  group2 as group,
  groupX,
  groupY,
  groupZ,
  hexagon,
  hexbin,
  hexgrid,
  hull,
  identity6 as identity,
  image,
  indexOf,
  initializer,
  interpolateNearest,
  interpolateNone,
  interpolatorBarycentric,
  interpolatorRandomWalk,
  legend,
  line,
  lineX,
  lineY,
  linearRegressionX,
  linearRegressionY,
  link3 as link,
  map5 as map,
  mapX,
  mapY,
  marks,
  normalize3 as normalize,
  normalizeX,
  normalizeY,
  numberInterval,
  plot,
  pointer,
  pointerX,
  pointerY,
  raster,
  rect,
  rectX,
  rectY,
  reverse2 as reverse,
  ruleX,
  ruleY,
  scale2 as scale,
  select,
  selectFirst,
  selectLast,
  selectMaxX,
  selectMaxY,
  selectMinX,
  selectMinY,
  shiftX,
  shiftY,
  shuffle2 as shuffle,
  sort2 as sort,
  sphere2 as sphere,
  spike,
  stackX,
  stackX1,
  stackX2,
  stackY,
  stackY1,
  stackY2,
  text,
  textX,
  textY,
  tickX,
  tickY,
  timeInterval2 as timeInterval,
  tip,
  basic as transform,
  tree,
  treeLink,
  treeNode,
  utcInterval,
  valueof,
  vector,
  vectorX,
  vectorY,
  voronoi,
  voronoiMesh,
  waffleX,
  waffleY,
  window2 as window,
  windowX,
  windowY
};
//# sourceMappingURL=@observablehq_plot.js.map
