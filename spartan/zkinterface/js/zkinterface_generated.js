// automatically generated by the FlatBuffers compiler, do not modify

/**
 * @const
 * @namespace
 */
var zkinterface = zkinterface || {};

/**
 * @enum {number}
 */
zkinterface.Message = {
  NONE: 0,
  Circuit: 1,
  R1CSConstraints: 2,
  Witness: 3
};

/**
 * @enum {string}
 */
zkinterface.MessageName = {
  '0': 'NONE',
  '1': 'Circuit',
  '2': 'R1CSConstraints',
  '3': 'Witness'
};

/**
 * @enum {number}
 */
zkinterface.CircuitType = {
  R1CS: 0,
  FanIn2: 1
};

/**
 * @enum {string}
 */
zkinterface.CircuitTypeName = {
  '0': 'R1CS',
  '1': 'FanIn2'
};

/**
 * A description of a circuit or sub-circuit.
 * This can be a complete circuit ready for proving,
 * or a part of a circuit being built.
 *
 * @constructor
 */
zkinterface.Circuit = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.Circuit}
 */
zkinterface.Circuit.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Circuit=} obj
 * @returns {zkinterface.Circuit}
 */
zkinterface.Circuit.getRootAsCircuit = function(bb, obj) {
  return (obj || new zkinterface.Circuit).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Circuit=} obj
 * @returns {zkinterface.Circuit}
 */
zkinterface.Circuit.getSizePrefixedRootAsCircuit = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.Circuit).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * Variables to use as connections to the sub-circuit.
 *
 * - Variables to use as input connections to the gadget.
 * - Or variables to use as output connections from the gadget.
 * - Variables are allocated by the sender of this message.
 * - The same structure must be provided for R1CS and witness generations.
 * - If `witness_generation=true`, variables must be assigned values.
 *
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables|null}
 */
zkinterface.Circuit.prototype.connections = function(obj) {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? (obj || new zkinterface.Variables).__init(this.bb.__indirect(this.bb_pos + offset), this.bb) : null;
};

/**
 * A variable ID greater than all IDs allocated by the sender of this message.
 * The recipient of this message can allocate new IDs >= free_variable_id.
 *
 * @returns {flatbuffers.Long}
 */
zkinterface.Circuit.prototype.freeVariableId = function() {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.readUint64(this.bb_pos + offset) : this.bb.createLong(0, 0);
};

/**
 * Whether a constraint system is being generated.
 * Provide constraints in R1CSConstraints messages.
 *
 * @returns {boolean}
 */
zkinterface.Circuit.prototype.r1csGeneration = function() {
  var offset = this.bb.__offset(this.bb_pos, 8);
  return offset ? !!this.bb.readInt8(this.bb_pos + offset) : false;
};

/**
 * Whether a witness is being generated.
 * Provide the witness in `connections.values` and Witness messages.
 *
 * @returns {boolean}
 */
zkinterface.Circuit.prototype.witnessGeneration = function() {
  var offset = this.bb.__offset(this.bb_pos, 10);
  return offset ? !!this.bb.readInt8(this.bb_pos + offset) : false;
};

/**
 * The largest element of the finite field used by the current system.
 * A canonical little-endian representation of the field order minus one.
 * See `Variables.values` below.
 *
 * @param {number} index
 * @returns {number}
 */
zkinterface.Circuit.prototype.fieldMaximum = function(index) {
  var offset = this.bb.__offset(this.bb_pos, 12);
  return offset ? this.bb.readUint8(this.bb.__vector(this.bb_pos + offset) + index) : 0;
};

/**
 * @returns {number}
 */
zkinterface.Circuit.prototype.fieldMaximumLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 12);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * @returns {Uint8Array}
 */
zkinterface.Circuit.prototype.fieldMaximumArray = function() {
  var offset = this.bb.__offset(this.bb_pos, 12);
  return offset ? new Uint8Array(this.bb.bytes().buffer, this.bb.bytes().byteOffset + this.bb.__vector(this.bb_pos + offset), this.bb.__vector_len(this.bb_pos + offset)) : null;
};

/**
 * Whether this is R1CS or arithmetic circuit.
 *
 * @returns {zkinterface.CircuitType}
 */
zkinterface.Circuit.prototype.circuitType = function() {
  var offset = this.bb.__offset(this.bb_pos, 14);
  return offset ? /** @type {zkinterface.CircuitType} */ (this.bb.readInt8(this.bb_pos + offset)) : zkinterface.CircuitType.R1CS;
};

/**
 * Optional: Any custom parameter that may influence the circuit construction.
 *
 * Example: function_name, if a gadget supports multiple function variants.
 * Example: the depth of a Merkle tree.
 * Counter-example: a Merkle path is not config and belongs in `connections.info`.
 *
 * @param {number} index
 * @param {zkinterface.KeyValue=} obj
 * @returns {zkinterface.KeyValue}
 */
zkinterface.Circuit.prototype.configuration = function(index, obj) {
  var offset = this.bb.__offset(this.bb_pos, 16);
  return offset ? (obj || new zkinterface.KeyValue).__init(this.bb.__indirect(this.bb.__vector(this.bb_pos + offset) + index * 4), this.bb) : null;
};

/**
 * @returns {number}
 */
zkinterface.Circuit.prototype.configurationLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 16);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.Circuit.startCircuit = function(builder) {
  builder.startObject(7);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} connectionsOffset
 */
zkinterface.Circuit.addConnections = function(builder, connectionsOffset) {
  builder.addFieldOffset(0, connectionsOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Long} freeVariableId
 */
zkinterface.Circuit.addFreeVariableId = function(builder, freeVariableId) {
  builder.addFieldInt64(1, freeVariableId, builder.createLong(0, 0));
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {boolean} r1csGeneration
 */
zkinterface.Circuit.addR1csGeneration = function(builder, r1csGeneration) {
  builder.addFieldInt8(2, +r1csGeneration, +false);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {boolean} witnessGeneration
 */
zkinterface.Circuit.addWitnessGeneration = function(builder, witnessGeneration) {
  builder.addFieldInt8(3, +witnessGeneration, +false);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} fieldMaximumOffset
 */
zkinterface.Circuit.addFieldMaximum = function(builder, fieldMaximumOffset) {
  builder.addFieldOffset(4, fieldMaximumOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<number>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.Circuit.createFieldMaximumVector = function(builder, data) {
  builder.startVector(1, data.length, 1);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addInt8(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.Circuit.startFieldMaximumVector = function(builder, numElems) {
  builder.startVector(1, numElems, 1);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {zkinterface.CircuitType} circuitType
 */
zkinterface.Circuit.addCircuitType = function(builder, circuitType) {
  builder.addFieldInt8(5, circuitType, zkinterface.CircuitType.R1CS);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} configurationOffset
 */
zkinterface.Circuit.addConfiguration = function(builder, configurationOffset) {
  builder.addFieldOffset(6, configurationOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<flatbuffers.Offset>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.Circuit.createConfigurationVector = function(builder, data) {
  builder.startVector(4, data.length, 4);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.Circuit.startConfigurationVector = function(builder, numElems) {
  builder.startVector(4, numElems, 4);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.Circuit.endCircuit = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} connectionsOffset
 * @param {flatbuffers.Long} freeVariableId
 * @param {boolean} r1csGeneration
 * @param {boolean} witnessGeneration
 * @param {flatbuffers.Offset} fieldMaximumOffset
 * @param {zkinterface.CircuitType} circuitType
 * @param {flatbuffers.Offset} configurationOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.Circuit.createCircuit = function(builder, connectionsOffset, freeVariableId, r1csGeneration, witnessGeneration, fieldMaximumOffset, circuitType, configurationOffset) {
  zkinterface.Circuit.startCircuit(builder);
  zkinterface.Circuit.addConnections(builder, connectionsOffset);
  zkinterface.Circuit.addFreeVariableId(builder, freeVariableId);
  zkinterface.Circuit.addR1csGeneration(builder, r1csGeneration);
  zkinterface.Circuit.addWitnessGeneration(builder, witnessGeneration);
  zkinterface.Circuit.addFieldMaximum(builder, fieldMaximumOffset);
  zkinterface.Circuit.addCircuitType(builder, circuitType);
  zkinterface.Circuit.addConfiguration(builder, configurationOffset);
  return zkinterface.Circuit.endCircuit(builder);
}

/**
 * R1CSConstraints represents constraints to be added to the constraint system.
 *
 * Multiple such messages are equivalent to the concatenation of `constraints` arrays.
 *
 * @constructor
 */
zkinterface.R1CSConstraints = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.R1CSConstraints}
 */
zkinterface.R1CSConstraints.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.R1CSConstraints=} obj
 * @returns {zkinterface.R1CSConstraints}
 */
zkinterface.R1CSConstraints.getRootAsR1CSConstraints = function(bb, obj) {
  return (obj || new zkinterface.R1CSConstraints).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.R1CSConstraints=} obj
 * @returns {zkinterface.R1CSConstraints}
 */
zkinterface.R1CSConstraints.getSizePrefixedRootAsR1CSConstraints = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.R1CSConstraints).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {number} index
 * @param {zkinterface.BilinearConstraint=} obj
 * @returns {zkinterface.BilinearConstraint}
 */
zkinterface.R1CSConstraints.prototype.constraints = function(index, obj) {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? (obj || new zkinterface.BilinearConstraint).__init(this.bb.__indirect(this.bb.__vector(this.bb_pos + offset) + index * 4), this.bb) : null;
};

/**
 * @returns {number}
 */
zkinterface.R1CSConstraints.prototype.constraintsLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * Optional: Any complementary info that may be useful.
 *
 * Example: human-readable descriptions.
 * Example: custom hints to an optimizer or analyzer.
 *
 * @param {number} index
 * @param {zkinterface.KeyValue=} obj
 * @returns {zkinterface.KeyValue}
 */
zkinterface.R1CSConstraints.prototype.info = function(index, obj) {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? (obj || new zkinterface.KeyValue).__init(this.bb.__indirect(this.bb.__vector(this.bb_pos + offset) + index * 4), this.bb) : null;
};

/**
 * @returns {number}
 */
zkinterface.R1CSConstraints.prototype.infoLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.R1CSConstraints.startR1CSConstraints = function(builder) {
  builder.startObject(2);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} constraintsOffset
 */
zkinterface.R1CSConstraints.addConstraints = function(builder, constraintsOffset) {
  builder.addFieldOffset(0, constraintsOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<flatbuffers.Offset>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.R1CSConstraints.createConstraintsVector = function(builder, data) {
  builder.startVector(4, data.length, 4);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.R1CSConstraints.startConstraintsVector = function(builder, numElems) {
  builder.startVector(4, numElems, 4);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} infoOffset
 */
zkinterface.R1CSConstraints.addInfo = function(builder, infoOffset) {
  builder.addFieldOffset(1, infoOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<flatbuffers.Offset>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.R1CSConstraints.createInfoVector = function(builder, data) {
  builder.startVector(4, data.length, 4);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.R1CSConstraints.startInfoVector = function(builder, numElems) {
  builder.startVector(4, numElems, 4);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.R1CSConstraints.endR1CSConstraints = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} constraintsOffset
 * @param {flatbuffers.Offset} infoOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.R1CSConstraints.createR1CSConstraints = function(builder, constraintsOffset, infoOffset) {
  zkinterface.R1CSConstraints.startR1CSConstraints(builder);
  zkinterface.R1CSConstraints.addConstraints(builder, constraintsOffset);
  zkinterface.R1CSConstraints.addInfo(builder, infoOffset);
  return zkinterface.R1CSConstraints.endR1CSConstraints(builder);
}

/**
 * Witness represents an assignment of values to variables.
 *
 * - Does not include variables already given in `Circuit.connections`.
 * - Does not include the constant one variable.
 * - Multiple such messages are equivalent to the concatenation of `Variables` arrays.
 *
 * @constructor
 */
zkinterface.Witness = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.Witness}
 */
zkinterface.Witness.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Witness=} obj
 * @returns {zkinterface.Witness}
 */
zkinterface.Witness.getRootAsWitness = function(bb, obj) {
  return (obj || new zkinterface.Witness).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Witness=} obj
 * @returns {zkinterface.Witness}
 */
zkinterface.Witness.getSizePrefixedRootAsWitness = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.Witness).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables|null}
 */
zkinterface.Witness.prototype.assignedVariables = function(obj) {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? (obj || new zkinterface.Variables).__init(this.bb.__indirect(this.bb_pos + offset), this.bb) : null;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.Witness.startWitness = function(builder) {
  builder.startObject(1);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} assignedVariablesOffset
 */
zkinterface.Witness.addAssignedVariables = function(builder, assignedVariablesOffset) {
  builder.addFieldOffset(0, assignedVariablesOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.Witness.endWitness = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} assignedVariablesOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.Witness.createWitness = function(builder, assignedVariablesOffset) {
  zkinterface.Witness.startWitness(builder);
  zkinterface.Witness.addAssignedVariables(builder, assignedVariablesOffset);
  return zkinterface.Witness.endWitness(builder);
}

/**
 * A single R1CS constraint between variables.
 *
 * - Represents the linear combinations of variables A, B, C such that:
 *       (A) * (B) = (C)
 * - A linear combination is given as a sequence of (variable ID, coefficient).
 *
 * @constructor
 */
zkinterface.BilinearConstraint = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.BilinearConstraint}
 */
zkinterface.BilinearConstraint.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.BilinearConstraint=} obj
 * @returns {zkinterface.BilinearConstraint}
 */
zkinterface.BilinearConstraint.getRootAsBilinearConstraint = function(bb, obj) {
  return (obj || new zkinterface.BilinearConstraint).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.BilinearConstraint=} obj
 * @returns {zkinterface.BilinearConstraint}
 */
zkinterface.BilinearConstraint.getSizePrefixedRootAsBilinearConstraint = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.BilinearConstraint).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables|null}
 */
zkinterface.BilinearConstraint.prototype.linearCombinationA = function(obj) {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? (obj || new zkinterface.Variables).__init(this.bb.__indirect(this.bb_pos + offset), this.bb) : null;
};

/**
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables|null}
 */
zkinterface.BilinearConstraint.prototype.linearCombinationB = function(obj) {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? (obj || new zkinterface.Variables).__init(this.bb.__indirect(this.bb_pos + offset), this.bb) : null;
};

/**
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables|null}
 */
zkinterface.BilinearConstraint.prototype.linearCombinationC = function(obj) {
  var offset = this.bb.__offset(this.bb_pos, 8);
  return offset ? (obj || new zkinterface.Variables).__init(this.bb.__indirect(this.bb_pos + offset), this.bb) : null;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.BilinearConstraint.startBilinearConstraint = function(builder) {
  builder.startObject(3);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} linearCombinationAOffset
 */
zkinterface.BilinearConstraint.addLinearCombinationA = function(builder, linearCombinationAOffset) {
  builder.addFieldOffset(0, linearCombinationAOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} linearCombinationBOffset
 */
zkinterface.BilinearConstraint.addLinearCombinationB = function(builder, linearCombinationBOffset) {
  builder.addFieldOffset(1, linearCombinationBOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} linearCombinationCOffset
 */
zkinterface.BilinearConstraint.addLinearCombinationC = function(builder, linearCombinationCOffset) {
  builder.addFieldOffset(2, linearCombinationCOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.BilinearConstraint.endBilinearConstraint = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} linearCombinationAOffset
 * @param {flatbuffers.Offset} linearCombinationBOffset
 * @param {flatbuffers.Offset} linearCombinationCOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.BilinearConstraint.createBilinearConstraint = function(builder, linearCombinationAOffset, linearCombinationBOffset, linearCombinationCOffset) {
  zkinterface.BilinearConstraint.startBilinearConstraint(builder);
  zkinterface.BilinearConstraint.addLinearCombinationA(builder, linearCombinationAOffset);
  zkinterface.BilinearConstraint.addLinearCombinationB(builder, linearCombinationBOffset);
  zkinterface.BilinearConstraint.addLinearCombinationC(builder, linearCombinationCOffset);
  return zkinterface.BilinearConstraint.endBilinearConstraint(builder);
}

/**
 * A description of multiple variables.
 *
 * - Each variable is identified by a numerical ID.
 * - Each variable can be assigned a concrete value.
 * - In `Circuit.connections`, the IDs indicate which variables are
 *   meant to be shared as inputs or outputs of a sub-circuit.
 * - During witness generation, the values form the assignment to the variables.
 * - In `BilinearConstraint` linear combinations, the values are the coefficients
 *   applied to variables in a linear combination.
 *
 * @constructor
 */
zkinterface.Variables = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.Variables}
 */
zkinterface.Variables.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables}
 */
zkinterface.Variables.getRootAsVariables = function(bb, obj) {
  return (obj || new zkinterface.Variables).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Variables=} obj
 * @returns {zkinterface.Variables}
 */
zkinterface.Variables.getSizePrefixedRootAsVariables = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.Variables).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * The IDs of the variables.
 *
 * - IDs must be unique within a constraint system.
 * - The ID 0 always represents the constant variable one.
 *
 * @param {number} index
 * @returns {flatbuffers.Long}
 */
zkinterface.Variables.prototype.variableIds = function(index) {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? this.bb.readUint64(this.bb.__vector(this.bb_pos + offset) + index * 8) : this.bb.createLong(0, 0);
};

/**
 * @returns {number}
 */
zkinterface.Variables.prototype.variableIdsLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * Optional: values assigned to variables.
 *
 * - Values are finite field elements as defined by `circuit.field_maximum`.
 * - Elements are represented in canonical little-endian form.
 * - Elements appear in the same order as variable_ids.
 * - Multiple elements are concatenated in a single byte array.
 * - The element representation may be truncated and its size shorter
 *   than `circuit.field_maximum`. Truncated bytes are treated as zeros.
 * - The size of an element representation is determined by:
 *
 *     element size = values.length / variable_ids.length
 *
 * @param {number} index
 * @returns {number}
 */
zkinterface.Variables.prototype.values = function(index) {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.readUint8(this.bb.__vector(this.bb_pos + offset) + index) : 0;
};

/**
 * @returns {number}
 */
zkinterface.Variables.prototype.valuesLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * @returns {Uint8Array}
 */
zkinterface.Variables.prototype.valuesArray = function() {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? new Uint8Array(this.bb.bytes().buffer, this.bb.bytes().byteOffset + this.bb.__vector(this.bb_pos + offset), this.bb.__vector_len(this.bb_pos + offset)) : null;
};

/**
 * Optional: Any complementary info that may be useful to the recipient.
 *
 * Example: human-readable names.
 * Example: custom variable typing information (`is_bit`, ...).
 * Example: a Merkle authentication path in some custom format.
 *
 * @param {number} index
 * @param {zkinterface.KeyValue=} obj
 * @returns {zkinterface.KeyValue}
 */
zkinterface.Variables.prototype.info = function(index, obj) {
  var offset = this.bb.__offset(this.bb_pos, 8);
  return offset ? (obj || new zkinterface.KeyValue).__init(this.bb.__indirect(this.bb.__vector(this.bb_pos + offset) + index * 4), this.bb) : null;
};

/**
 * @returns {number}
 */
zkinterface.Variables.prototype.infoLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 8);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.Variables.startVariables = function(builder) {
  builder.startObject(3);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} variableIdsOffset
 */
zkinterface.Variables.addVariableIds = function(builder, variableIdsOffset) {
  builder.addFieldOffset(0, variableIdsOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<flatbuffers.Long>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.Variables.createVariableIdsVector = function(builder, data) {
  builder.startVector(8, data.length, 8);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addInt64(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.Variables.startVariableIdsVector = function(builder, numElems) {
  builder.startVector(8, numElems, 8);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} valuesOffset
 */
zkinterface.Variables.addValues = function(builder, valuesOffset) {
  builder.addFieldOffset(1, valuesOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<number>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.Variables.createValuesVector = function(builder, data) {
  builder.startVector(1, data.length, 1);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addInt8(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.Variables.startValuesVector = function(builder, numElems) {
  builder.startVector(1, numElems, 1);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} infoOffset
 */
zkinterface.Variables.addInfo = function(builder, infoOffset) {
  builder.addFieldOffset(2, infoOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<flatbuffers.Offset>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.Variables.createInfoVector = function(builder, data) {
  builder.startVector(4, data.length, 4);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.Variables.startInfoVector = function(builder, numElems) {
  builder.startVector(4, numElems, 4);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.Variables.endVariables = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} variableIdsOffset
 * @param {flatbuffers.Offset} valuesOffset
 * @param {flatbuffers.Offset} infoOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.Variables.createVariables = function(builder, variableIdsOffset, valuesOffset, infoOffset) {
  zkinterface.Variables.startVariables(builder);
  zkinterface.Variables.addVariableIds(builder, variableIdsOffset);
  zkinterface.Variables.addValues(builder, valuesOffset);
  zkinterface.Variables.addInfo(builder, infoOffset);
  return zkinterface.Variables.endVariables(builder);
}

/**
 * Generic key-value for custom attributes.
 *
 * @constructor
 */
zkinterface.KeyValue = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.KeyValue}
 */
zkinterface.KeyValue.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.KeyValue=} obj
 * @returns {zkinterface.KeyValue}
 */
zkinterface.KeyValue.getRootAsKeyValue = function(bb, obj) {
  return (obj || new zkinterface.KeyValue).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.KeyValue=} obj
 * @returns {zkinterface.KeyValue}
 */
zkinterface.KeyValue.getSizePrefixedRootAsKeyValue = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.KeyValue).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.Encoding=} optionalEncoding
 * @returns {string|Uint8Array|null}
 */
zkinterface.KeyValue.prototype.key = function(optionalEncoding) {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? this.bb.__string(this.bb_pos + offset, optionalEncoding) : null;
};

/**
 * @param {number} index
 * @returns {number}
 */
zkinterface.KeyValue.prototype.value = function(index) {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.readUint8(this.bb.__vector(this.bb_pos + offset) + index) : 0;
};

/**
 * @returns {number}
 */
zkinterface.KeyValue.prototype.valueLength = function() {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.__vector_len(this.bb_pos + offset) : 0;
};

/**
 * @returns {Uint8Array}
 */
zkinterface.KeyValue.prototype.valueArray = function() {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? new Uint8Array(this.bb.bytes().buffer, this.bb.bytes().byteOffset + this.bb.__vector(this.bb_pos + offset), this.bb.__vector_len(this.bb_pos + offset)) : null;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.KeyValue.startKeyValue = function(builder) {
  builder.startObject(2);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} keyOffset
 */
zkinterface.KeyValue.addKey = function(builder, keyOffset) {
  builder.addFieldOffset(0, keyOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} valueOffset
 */
zkinterface.KeyValue.addValue = function(builder, valueOffset) {
  builder.addFieldOffset(1, valueOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {Array.<number>} data
 * @returns {flatbuffers.Offset}
 */
zkinterface.KeyValue.createValueVector = function(builder, data) {
  builder.startVector(1, data.length, 1);
  for (var i = data.length - 1; i >= 0; i--) {
    builder.addInt8(data[i]);
  }
  return builder.endVector();
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {number} numElems
 */
zkinterface.KeyValue.startValueVector = function(builder, numElems) {
  builder.startVector(1, numElems, 1);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.KeyValue.endKeyValue = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} keyOffset
 * @param {flatbuffers.Offset} valueOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.KeyValue.createKeyValue = function(builder, keyOffset, valueOffset) {
  zkinterface.KeyValue.startKeyValue(builder);
  zkinterface.KeyValue.addKey(builder, keyOffset);
  zkinterface.KeyValue.addValue(builder, valueOffset);
  return zkinterface.KeyValue.endKeyValue(builder);
}

/**
 * @constructor
 */
zkinterface.Root = function() {
  /**
   * @type {flatbuffers.ByteBuffer}
   */
  this.bb = null;

  /**
   * @type {number}
   */
  this.bb_pos = 0;
};

/**
 * @param {number} i
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {zkinterface.Root}
 */
zkinterface.Root.prototype.__init = function(i, bb) {
  this.bb_pos = i;
  this.bb = bb;
  return this;
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Root=} obj
 * @returns {zkinterface.Root}
 */
zkinterface.Root.getRootAsRoot = function(bb, obj) {
  return (obj || new zkinterface.Root).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @param {zkinterface.Root=} obj
 * @returns {zkinterface.Root}
 */
zkinterface.Root.getSizePrefixedRootAsRoot = function(bb, obj) {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new zkinterface.Root).__init(bb.readInt32(bb.position()) + bb.position(), bb);
};

/**
 * @param {flatbuffers.ByteBuffer} bb
 * @returns {boolean}
 */
zkinterface.Root.bufferHasIdentifier = function(bb) {
  return bb.__has_identifier('zkif');
};

/**
 * @returns {zkinterface.Message}
 */
zkinterface.Root.prototype.messageType = function() {
  var offset = this.bb.__offset(this.bb_pos, 4);
  return offset ? /** @type {zkinterface.Message} */ (this.bb.readUint8(this.bb_pos + offset)) : zkinterface.Message.NONE;
};

/**
 * @param {flatbuffers.Table} obj
 * @returns {?flatbuffers.Table}
 */
zkinterface.Root.prototype.message = function(obj) {
  var offset = this.bb.__offset(this.bb_pos, 6);
  return offset ? this.bb.__union(obj, this.bb_pos + offset) : null;
};

/**
 * @param {flatbuffers.Builder} builder
 */
zkinterface.Root.startRoot = function(builder) {
  builder.startObject(2);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {zkinterface.Message} messageType
 */
zkinterface.Root.addMessageType = function(builder, messageType) {
  builder.addFieldInt8(0, messageType, zkinterface.Message.NONE);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} messageOffset
 */
zkinterface.Root.addMessage = function(builder, messageOffset) {
  builder.addFieldOffset(1, messageOffset, 0);
};

/**
 * @param {flatbuffers.Builder} builder
 * @returns {flatbuffers.Offset}
 */
zkinterface.Root.endRoot = function(builder) {
  var offset = builder.endObject();
  return offset;
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} offset
 */
zkinterface.Root.finishRootBuffer = function(builder, offset) {
  builder.finish(offset, 'zkif');
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {flatbuffers.Offset} offset
 */
zkinterface.Root.finishSizePrefixedRootBuffer = function(builder, offset) {
  builder.finish(offset, 'zkif', true);
};

/**
 * @param {flatbuffers.Builder} builder
 * @param {zkinterface.Message} messageType
 * @param {flatbuffers.Offset} messageOffset
 * @returns {flatbuffers.Offset}
 */
zkinterface.Root.createRoot = function(builder, messageType, messageOffset) {
  zkinterface.Root.startRoot(builder);
  zkinterface.Root.addMessageType(builder, messageType);
  zkinterface.Root.addMessage(builder, messageOffset);
  return zkinterface.Root.endRoot(builder);
}

// Exports for Node.js and RequireJS
this.zkinterface = zkinterface;
