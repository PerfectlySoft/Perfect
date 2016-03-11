//
//  PlayerBot.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-11-16.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import Darwin

class PlayerBotRandom: Player {
	
	init(gameId: Int, type: PieceType) {
		super.init(nick: "Random-Bot", gameId: gameId, type: type)
	}
	
	func move(gameState: GameState) {
		let (_, _, x, y) = gameState.currentPlayer(self.gameId)
		if x != INVALID_ID {
			let boardId = gameState.boardId(gameId, x: x, y: y)
			return self.moveOnBoard(gameState, boardId: boardId)
		}
		// we can move on any board
		// pick an unowned board at random
		var boards = [Int]()
		for x in 0..<3 {
			for y in 0..<3 {
				let boardId = gameState.boardId(self.gameId, x: x, y: y)
				let boardOwner = gameState.boardOwner(boardId)
				if boardOwner == .None {
					boards.append(boardId)
				}
			}
		}
		guard boards.count > 0 else {
			fatalError("It's my turn but there are no valid boards on which to play")
		}
		let rnd = arc4random_uniform(UInt32(boards.count))
		let boardId = boards[Int(rnd)]
		self.moveOnBoard(gameState, boardId: boardId)
	}
	
	private func moveOnBoard(gameState: GameState, boardId: Int) {
		// find a random slot
		var slots = [Int]()
		for x in 0..<3 {
			for y in 0..<3 {
				let slotId = gameState.slotId(boardId, x: x, y: y)
				let slotOwner = gameState.slotOwner(slotId)
				if slotOwner == .None {
					slots.append(slotId)
				}
			}
		}
		guard slots.count > 0 else {
			fatalError("It's my turn but there are no valid slots on which to play")
		}
		let rnd = arc4random_uniform(UInt32(slots.count))
		let slotId = slots[Int(rnd)]
		gameState.setSlotOwner(slotId, type: self.type)
	}
}

